import asyncio
import json
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from io import StringIO
from itertools import count

import httpx
import pytest
from fastapi.testclient import TestClient

from app import orchestrator
from app.email_parser import analyze_raw_email
from app.engines import forensics
from app.engines.heuristics import lexical_findings
from app.engines.threat_intel import query_all_threat_feeds
from app.intel import Indicator, lookup_snapshot, parse_openphish, parse_stix, snapshot_document
from app.main import app
from app.scoring import assess, finding
from app.security import HoneypotTrapTriggered, normalize_target
from scripts.refresh_intel import save_snapshot


CLIENT_IDS = count(1)


class FixedClock(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 11, 26, 8, 0, tzinfo=timezone.utc).astimezone(tz)


@pytest.fixture
def offline_client(monkeypatch):
    dates = {"fresh.co.in": "2026-11-26T12:00:00+05:30", "github.com": "2010-01-01T00:00:00Z"}

    def respond(request):
        assert request.method == "GET"
        assert request.url.host in {"rdap.nixiregistry.in", "rdap.verisign.com"}
        domain = request.url.path.split("/")[-1]
        if domain not in dates:
            return httpx.Response(404)
        return httpx.Response(200, json={
            "ldhName": domain,
            "events": [{"eventAction": "registration", "eventDate": dates[domain]}],
        })

    async def lookup(client, domain):
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as mock_client:
            return await forensics.lookup_whois_rdap(mock_client, domain)

    monkeypatch.setattr(forensics, "datetime", FixedClock)
    monkeypatch.setattr(forensics, "raw_socket_whois", lambda domain: {})
    monkeypatch.setattr(orchestrator, "lookup_whois_rdap", lookup)
    for name in ("PHISHMATRIX_DNS_LOOKUPS", "PHISHMATRIX_INTEL_FILE", "VT_API_KEY", "ABUSECH_AUTH_KEY", "ABUSEIPDB_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    with TestClient(app, client=(f'fixture-{next(CLIENT_IDS)}', 50000)) as client:
        yield client, dates


@pytest.mark.parametrize(("date", "days", "within_24"), [
    ("2026-11-26T12:00:00+05:30", 0, True),
    ("2026-11-25T14:00:00Z", 0, True),
    ("2026-11-25T08:00:00Z", 1, False),
    ("2026-11-26", 0, True),
    ("2026-10-27T08:00:00Z", 30, False),
    ("2026-10-26T08:00:00Z", 31, False),
    ("2026-11-27T08:00:00Z", None, None),
    ("invalid", None, None),
])
def test_registration_dates_and_registered_domain(monkeypatch, date, days, within_24):
    monkeypatch.setattr(forensics, "datetime", FixedClock)
    monkeypatch.setattr(forensics, "raw_socket_whois", lambda domain: {})

    def respond(request):
        assert str(request.url) == "https://rdap.nixiregistry.in/rdap/domain/fresh.co.in"
        return httpx.Response(200, json={"ldhName": "fresh.co.in", "events": [
            {"eventAction": "registration", "eventDate": date},
            {"eventAction": "last changed", "eventDate": "2026-11-26T07:55:00Z"},
        ]})

    async def scan():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            return await forensics.lookup_whois_rdap(client, "login.fresh.co.in")

    result = asyncio.run(scan())
    assert result["queried_domain"] == "fresh.co.in"
    assert result["domain_age_days"] == days
    assert result["is_registered_within_24h"] is within_24
    assert result["is_newly_registered"] == (days <= 30 if days is not None else None)


def test_registry_bootstrap_ignores_non_https(monkeypatch):
    monkeypatch.setattr(forensics, "bootstrap_cache", {"retry_at": 0.0, "services": {}})

    def respond(request):
        assert str(request.url) == forensics.RDAP_BOOTSTRAP
        return httpx.Response(200, json={"services": [
            [["xyz"], ["http://insecure.example/", "https://rdap.safe.example/"]],
            [["app"], ["https://192.0.2.3/"]],
        ]})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            assert await forensics.registry_base(client, "xyz") == "https://rdap.safe.example/"
            assert await forensics.registry_base(client, "app") is None

    asyncio.run(run())


def test_rdap_timeout_uses_whois_and_keeps_source(monkeypatch):
    monkeypatch.setattr(forensics, "datetime", FixedClock)

    def whois(domain):
        assert domain == "fresh.co.in"
        return {"creation_date": "2026-11-26", "registrar": "Fixture"}

    monkeypatch.setattr(forensics, "raw_socket_whois", whois)

    async def scan():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(429))) as client:
            return await forensics.lookup_whois_rdap(client, "login.fresh.co.in")

    result = asyncio.run(scan())
    assert result["registration_source"] == "WHOIS"
    assert result["is_registered_within_24h"] is True
    assert result["registration_timestamp"] is None


def test_same_day_in_url_bulk_and_cli(offline_client):
    client, _ = offline_client
    url = "https://login.fresh.co.in/?token=fixture-private"
    response = client.post("/api/v1/scan", json={"url": url})
    assert response.status_code == 200
    result = response.json()
    assert result["risk_score"] == 40
    assert result["verdict"] == "SUSPICIOUS"
    assert result["domain_age"] == "Under 24 hours (2026-11-26 · RDAP)"
    assert result["summary"]["evidence"][0]["rule_id"] == "NRD_24H"
    assert result["siem_event"]["related"]["hosts"] == ["login.fresh.co.in"]
    assert "dns" not in result["siem_event"]
    assert "fixture-private" not in response.text
    assert "<rule" in result["soc_arsenal"]["wazuh_rule"]
    bulk = client.post("/api/v1/bulk-scan", json={"urls": [url, "http://127.0.0.1"]}).json()["results"]
    assert bulk[0]["verdict"] == "SUSPICIOUS"
    assert bulk[1]["verdict"] == "BLOCKED"
    cli = client.post("/cli", json={"url": url})
    assert "[SUSPICIOUS]" in cli.text
    assert "Under 24 hours" in cli.text


def test_allowlist_cannot_skip_age_and_unknown_is_inconclusive(offline_client):
    client, dates = offline_client
    initial = client.post("/api/v1/scan", json={"url": "github.com"}).json()
    assert initial["scan_metadata"]["whitelist_fast_path"]
    assert initial["verdict"] == "INCONCLUSIVE"
    dates["github.com"] = "2026-11-26T07:20:00Z"
    current = client.post("/api/v1/scan", json={"url": "github.com"}).json()
    assert current["verdict"] == "SUSPICIOUS"
    assert not current["scan_metadata"]["whitelist_fast_path"]
    assert client.post("/api/v1/scan", json={"url": "unknown.com"}).json()["verdict"] == "INCONCLUSIVE"


@pytest.mark.parametrize("indicator", [
    "http://127.0.0.1",
    "http://[::1]",
    "http://169.254.169.254",
    "http://localhost.localdomain/",
    "ftp://example.com/a",
    "https://example.com/<script>sample</script>",
    "https://example.com/?q=' OR 1=1--",
    "https://user@example.com/",
])
def test_lol_traps_do_not_reflect_input(offline_client, indicator):
    client, _ = offline_client
    response = client.post("/api/v1/scan", json={"url": indicator})
    assert response.status_code == 418
    assert "LOL" in response.json()["detail"]
    assert "payload" not in response.json()
    assert indicator not in response.text
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_literal_ip_and_idna_are_canonicalized():
    assert normalize_target("8.8.8.8", resolve=False)["resolved_ip"] == "8.8.8.8"
    assert normalize_target("https://BÜCHER.de/", resolve=False)["domain"] == "xn--bcher-kva.de"
    with pytest.raises(HoneypotTrapTriggered):
        normalize_target("http://[::ffff:127.0.0.1]/", resolve=False)


def test_request_limits_csp_and_origin(offline_client):
    client, _ = offline_client
    root = client.get("/")
    assert root.status_code == 200
    assert "frame-ancestors 'none'" in root.headers["Content-Security-Policy"]
    assert "unsafe-inline" not in root.headers["Content-Security-Policy"]
    assert client.get("/admin").status_code == 418
    assert client.get("/static/workbench.js").status_code == 200
    assert client.post("/api/v1/scan", json={"url": "github.com"}, headers={"Origin": "https://other.example"}).status_code == 403
    assert client.post("/api/v1/scan", data={"url": "github.com"}).status_code == 415
    large = [b"0" * 70000, b"0" * 70000]
    assert client.post("/api/v1/html-scan", content=iter(large), headers={"Content-Type": "application/json"}).status_code == 413
    invalid = client.post("/api/v1/scan", json={"url": {"sensitive": "secret-fixture"}})
    assert invalid.status_code == 422 and "secret-fixture" not in invalid.text
    assert client.get("/api/v1/rules").json()["ruleset_version"] == client.get("/health").json()["version"]


def test_rate_limit_is_bounded():
    with TestClient(app, client=(f'fixture-{next(CLIENT_IDS)}', 50000)) as client:
        responses = [client.post("/api/v1/html-scan", json={"html": "<p>Fixture</p>"}) for _ in range(31)]
    assert responses[-2].status_code == 200
    assert responses[-1].status_code == 429
    assert responses[-1].headers["Retry-After"] == "60"


def test_passive_provider_requests_carry_no_submitted_path_or_query(monkeypatch):
    for key in ("VT_API_KEY", "ABUSECH_AUTH_KEY", "ABUSEIPDB_API_KEY"):
        monkeypatch.setenv(key, "fixture")
    monkeypatch.setenv("PHISHMATRIX_VT_SHARE", "1")
    hosts = set()

    def respond(request):
        assert "private-secret" not in str(request.url)
        assert b"private-secret" not in request.content
        assert "suspicious.com" != request.url.host
        assert request.url.scheme == "https"
        hosts.add(request.url.host)
        return httpx.Response(503)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            return await query_all_threat_feeds(client, "https://suspicious.com/private-secret?q=private-secret", "suspicious.com", "8.8.8.8")

    outcomes = asyncio.run(run())
    assert hosts == {"www.virustotal.com", "api.abuseipdb.com", "threatfox-api.abuse.ch", "urlhaus-api.abuse.ch"}
    assert all(outcomes[name]["status"] == "Unavailable" for name in ("virustotal", "abuseipdb", "threatfox", "urlhaus"))


def test_snapshot_exact_match_respects_expiry_and_scope(tmp_path, monkeypatch, offline_client):
    client, _ = offline_client
    now = datetime.now(timezone.utc)
    url = "https://test-ioc.example/test"
    path = tmp_path / "index.json"
    records = parse_openphish(url + "\n" + url + "\nnot-a-url", now)
    assert len(records) == 1
    records.append(Indicator("url", "https://test-ioc.example/old", "Analyst STIX", (now - timedelta(minutes=1)).isoformat()))
    save_snapshot(path, snapshot_document(records, now))
    monkeypatch.setenv("PHISHMATRIX_INTEL_FILE", str(path))
    output = lookup_snapshot(url, "test-ioc.example", None)
    assert output["hits"][0]["scope"] == "url"
    assert lookup_snapshot(url + "ing", "test-ioc.example", None)["status"] == "No match"
    assert lookup_snapshot("https://test-ioc.example/old", "test-ioc.example", None)["status"] == "No match"
    result = client.post("/api/v1/scan", json={"url": url}).json()
    assert result["verdict"] == "MALICIOUS"
    assert result["evidence"][0]["rule_id"] == "TI_URL_EXACT"


def test_stix_rejects_revoked_and_complex_patterns():
    now = datetime.now(timezone.utc)
    default = {
        "type": "indicator", "pattern_type": "stix",
        "valid_from": (now - timedelta(days=1)).isoformat(),
        "valid_until": (now + timedelta(days=1)).isoformat(),
    }
    valid = {**default, "pattern": "[domain-name:value = 'review.example']"}
    bundle = {"type": "bundle", "objects": [
        valid,
        {**valid, "revoked": True},
        {**valid, "pattern": "[domain-name:value MATCHES '.*']"},
        {**valid, "valid_until": (now - timedelta(seconds=1)).isoformat()},
    ]}
    records = parse_stix(bundle, now)
    assert [record.value for record in records] == ["review.example"]


def test_provider_overlap_and_weak_signals_do_not_force_malicious():
    result = assess([
        finding("NRD_24H", "RDAP", "registration"),
        finding("TI_DOMAIN", "Provider 1", "match"),
        finding("TI_DOMAIN", "Provider 2", "match"),
    ], coverage_sufficient=True)
    assert result["verdict"] == "SUSPICIOUS"
    assert result["contributions"]["domain_reputation"] == 35


def test_offline_html_cross_domain_form_and_normal_password_form(offline_client):
    client, _ = offline_client
    risky = '<title>Test</title><form action="https://receiver.example/session"><input type="password"></form>'
    normal = '<form action="/session"><input type="password"></form>'
    context = "https://sender.example/login"
    result = client.post("/api/v1/html-scan", json={"html": risky, "url": context}).json()
    assert result["verdict"] == "SUSPICIOUS"
    assert result["evidence"][0]["rule_id"] == "HTML_CROSS_ORIGIN_FORM"
    assert result["dom_forensics"]["network_activity"] == "None"
    result = client.post("/api/v1/html-scan", json={"html": normal, "url": context}).json()
    assert result["risk_score"] == 0


def test_email_body_link_and_auth_claim_alone_add_no_points():
    report = analyze_raw_email(
        "From: Sender <sender@example.com>\n"
        "Authentication-Results: untrusted.example; spf=fail\n"
        "Subject: Report\n\n"
        "Read https://example.com/report?token=fixture-private"
    )
    assert report["risk_score"] == 0
    assert not report["authentication_verified"]
    assert report["extracted_urls"] == ["hxxps://example[.]com/report"]
    assert "fixture-private" not in json.dumps(report)

def test_confusable_brand_is_suspicious_and_unrelated_idn_is_context_only():
    confusion = assess(lexical_findings("paypa1.com", "/", ""), coverage_sufficient=False)
    legitimate = assess(lexical_findings("xn--bcher-kva.de", "/", ""), coverage_sufficient=True)
    assert confusion["verdict"] == "SUSPICIOUS"
    assert confusion["evidence"][0]["rule_id"] == "BRAND_CONFUSABLE"
    assert legitimate["risk_score"] == 0


@pytest.mark.parametrize(("url", "rule"), [
    ("https://microsoft.updates.example.com/signin", "URL_BRAND_SUBDOMAIN"),
    ("http://8.8.8.8/login", "URL_IP_LOGIN"),
])
def test_added_url_rules(url, rule):
    target = normalize_target(url, resolve=False)
    evidence = lexical_findings(target["domain"], target["path"], target["query"])
    assert rule in {entry.rule_id for entry in evidence}
    assert assess(evidence, coverage_sufficient=False)["verdict"] == "SUSPICIOUS"
    assert not lexical_findings("login.microsoft.com", "/signin", "")
    assert not lexical_findings("8.8.8.8", "/help", "")


def test_email_attachment_metadata_distinguishes_document_from_executable():
    body = (
        "From: analyst@example.com\n"
        "Content-Type: application/octet-stream\n"
        'Content-Disposition: attachment; filename="{}"\n\nfixture'
    )
    risky = analyze_raw_email(body.format("statement.pdf.exe"))
    benign = analyze_raw_email(body.format("statement.v2.pdf"))
    assert risky["evidence"][0]["rule_id"] == "EMAIL_DOUBLE_EXTENSION"
    assert risky["verdict"] == "SUSPICIOUS"
    assert benign["evidence"] == []


def test_html_base_and_http_credential_rules(offline_client):
    client, _ = offline_client
    html = '<base href="http://receiver.example/"><form action="submit"><input type="password"></form>'
    result = client.post("/api/v1/html-scan", json={"html": html, "url": "https://login.example/"}).json()
    assert {item["rule_id"] for item in result["evidence"]} == {
        "HTML_CREDENTIAL_FORM_REDIRECT", "HTML_INSECURE_PASSWORD"
    }
    assert result["verdict"] == "SUSPICIOUS"


def test_model_context_does_not_override_verdict(offline_client):
    client, _ = offline_client
    data = client.post("/api/v1/scan", json={"url": "https://login.fresh.co.in"}).json()
    assert 0 <= data["dataset_model"]["score"] <= 1
    assert data["risk_score"] == 40


def test_host_no_match_cannot_clear_a_page(offline_client, monkeypatch):
    client, dates = offline_client
    dates["example.com"] = "2010-01-01T00:00:00Z"

    async def feeds(*args):
        return {
            "threatfox": {"scope": "domain", "status": "No match"},
            "webrisk": {"scope": "domain", "status": "Access denied"},
            "urlhaus_url": {"scope": "url", "status": "No match"},
        }

    monkeypatch.setattr(orchestrator, "query_all_threat_feeds", feeds)
    result = client.post("/api/v1/scan", json={"url": "https://example.com/some/page"}).json()

    assert result["risk_score"] == 0
    assert result["verdict"] == "INCONCLUSIVE"
    assert not result["reputation_coverage"]["sufficient_for_no_match"]
    assert "No completed URL-level" in result["executive_summary"]


def test_completed_url_reputation_reports_no_listing(offline_client, monkeypatch):
    client, _ = offline_client

    async def feeds(*args):
        return {"webrisk": {"scope": "url", "status": "No match"}}

    monkeypatch.setattr(orchestrator, "query_all_threat_feeds", feeds)
    result = client.post("/api/v1/scan", json={"url": "https://example.com/provider-check"}).json()

    assert result["verdict"] == "CLEAN"
    assert result["reputation_coverage"]["negative_sources"] == ["Google Web Risk"]
    assert result["executive_summary"] == "No match from Google Web Risk for this URL."


def test_historical_index_matches_a_path_without_clearing_the_host(offline_client, monkeypatch):
    from app import historical_intel
    from scripts.build_historical_index import build_index

    client, _ = offline_client
    csv_file = StringIO(
        "url,type\n"
        "example.com/archived,phishing\n"
        "example.com/conflict,malware\n"
        "example.com/conflict,benign\n"
    )
    monkeypatch.setattr("scripts.build_historical_index.open_csv", lambda *args: nullcontext(csv_file))
    index, counts = build_index(None)
    monkeypatch.setattr(historical_intel, "read_index", lambda: index)
    assert counts["conflicting_keys_omitted"] == 1

    archived = client.post("/api/v1/scan", json={"url": "http://example.com/archived"}).json()
    assert archived["verdict"] == "SUSPICIOUS"
    assert archived["risk_score"] == 30
    assert archived["providers"]["Kaggle historical index"]["labels"] == ["phishing"]
    for suffix in ("", "/another-page", "/conflict", "/archived?token=test"):
        response = client.post("/api/v1/scan", json={"url": "https://example.com" + suffix}).json()
        assert response["providers"]["Kaggle historical index"]["status"] == "No historical match"
        assert response["verdict"] == "INCONCLUSIVE"
