import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest

from app.engines.analyst import summarize
from app.engines.legacy_intel import KEYS, additional_lookups, malshare_lookup
from app.engines.provider_http import request_json
from app.engines.threat_intel import query_all_threat_feeds


@pytest.fixture
def keys(monkeypatch):
    for name in (*KEYS.values(), "VT_API_KEY", "ABUSEIPDB_API_KEY", "ABUSECH_AUTH_KEY",
                 "GROQ_API_KEY", "GEMINI_API_KEY", "OPENROUTER_API_KEY"):
        monkeypatch.setenv(name, "fixture-" + name)
    monkeypatch.setenv("HTTPBL_API_KEY", "abcdefghijkl")
    monkeypatch.setenv("PHISHMATRIX_VT_SHARE", "1")
    monkeypatch.setenv("PHISHMATRIX_PUBLIC_INTEL", "1")
    monkeypatch.setenv("PHISHMATRIX_AI_SUMMARY", "1")


def perform(handler, operation):
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await operation(client)
    return asyncio.run(run())


def test_all_lookup_keys_use_intended_transport_and_sanitize_results(keys, monkeypatch):
    async def resolver(question, rdtype, **kwargs):
        assert question == "abcdefghijkl.8.8.8.8.dnsbl.httpbl.org."
        assert rdtype == "A"
        return [SimpleNamespace(address="127.4.30.2")]

    monkeypatch.setattr("app.engines.legacy_intel.dns.asyncresolver.resolve", resolver)
    expected = {
        "www.virustotal.com": ("x-apikey", "VT_API_KEY", {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}),
        "api.abuseipdb.com": ("key", "ABUSEIPDB_API_KEY", {"data": {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 0}}),
        "threatfox-api.abuse.ch": ("auth-key", "ABUSECH_AUTH_KEY", {"query_status": "no_result"}),
        "urlhaus-api.abuse.ch": ("auth-key", "ABUSECH_AUTH_KEY", {"query_status": "no_results"}),
        "webrisk.googleapis.com": ("x-goog-api-key", "WEBRISK_API_KEY", {}),
        "urlscan.io": ("api-key", "URLSCAN_API_KEY", {"results": [{"task": {"url": "private-provider-field"}}]}),
        "otx.alienvault.com": ("x-otx-api-key", "OTX_API_KEY", {"pulse_info": {"count": 1}}),
        "pulsedive.com": ("?key", "PULSEDIVE_API_KEY", {"risk": "high"}),
        "api.greynoise.io": ("key", "GREYNOISE_API_KEY", {"classification": "malicious"}),
        "api.shodan.io": ("?key", "SHODAN_API_KEY", {"ports": [80]}),
        "api.apilayer.net": ("?access_key", "MAILBOXLAYER_API_KEY", {"mx_found": True}),
        "pro.ip-api.com": ("?key", "IP_API_KEY", {"status": "success"}),
        "crt.sh": (None, None, [{"id": 123}]),
        "cavalier.hudsonrock.com": (None, None, {"total": 2, "stealers": ["private-provider-field"]}),
    }
    visits = set()

    def route(request):
        assert request.url.scheme == "https"
        assert "sensitive-path" not in str(request.url)
        assert "private-token" not in str(request.url)
        host = request.url.host
        visits.add(host)
        if host == "api.apilayer.net":
            assert request.url.path == "/mailboxlayer/api/check"
            assert request.url.params["email"] == "postmaster@example.com"
            assert request.url.params["smtp"] == "0"
        param, name, payload = expected[host]
        if param:
            actual = request.url.params[param[1:]] if param.startswith("?") else request.headers[param]
            assert actual == "fixture-" + name
        return httpx.Response(200, json=payload)

    result = perform(route, lambda client: query_all_threat_feeds(
        client, "https://example.com/sensitive-path?token=private-token", "example.com", "8.8.8.8"
    ))
    assert visits == expected.keys()
    assert result["httpbl"]["status"] == "Match"
    assert result["malshare"]["status"] == "Hash lookup available"
    assert result["mailboxlayer"] == {"status": "Observed", "scope": "domain", "mx_found": True}
    assert result["urlscan"]["status"] == "Observed"
    assert result["crtsh"]["certificate_count"] == 1
    assert result["hudsonrock"]["aggregate_records"] == 2
    assert "fixture-" not in json.dumps(result)
    assert "private-provider-field" not in json.dumps(result)


def test_webrisk_status_and_opt_in_path(keys, monkeypatch):
    monkeypatch.setenv("PHISHMATRIX_WEBRISK_PATH_SHARE", "1")

    def route(request):
        if request.url.host == "webrisk.googleapis.com":
            assert request.url.params["uri"] == "https://example.com/path"
            return httpx.Response(200, json={"threat": {"threatTypes": ["SOCIAL_ENGINEERING"]}})
        return httpx.Response(429)

    result = perform(route, lambda client: additional_lookups(
        client, "https://example.com/path?sensitive=token", "example.com", None, "domain"
    ))
    assert result["webrisk"]["scope"] == "domain"
    assert result["webrisk"]["status"] == "Match"
    assert result["urlscan"]["status"] == "Rate limited"
    assert result["greynoise"]["status"] == "No IP"


def test_fixed_connectors_do_not_follow_redirects():
    def route(request):
        assert request.url.host == "example.com"
        return httpx.Response(302, headers={"Location": "https://example.org/"})

    status, data = perform(route, lambda client: request_json(client, "GET", "https://example.com/"))
    assert (status, data) == (302, {})


def test_malshare_only_looks_up_metadata(keys):
    digest = "a" * 64

    def route(request):
        assert request.url.host == "malshare.com"
        assert request.url.params["action"] == "details"
        assert request.url.params["hash"] == digest
        return httpx.Response(200, json={"SHA256": digest, "source": "do not expose"})

    result = perform(route, lambda client: malshare_lookup(client, digest))
    assert result == {"status": "Match", "scope": "hash"}


@pytest.mark.parametrize("winner", ["Groq", "Gemini", "OpenRouter"])
def test_ai_fallback_only_sends_builtin_evidence(keys, winner):
    attempted = []

    def route(request):
        name = {"api.groq.com": "Groq", "generativelanguage.googleapis.com": "Gemini", "openrouter.ai": "OpenRouter"}[request.url.host]
        attempted.append(name)
        body = request.content.decode()
        assert "uploaded-email-body" not in body
        assert "private-target.example" not in body
        assert "NRD_24H" in body
        if name != winner:
            return httpx.Response(429)
        if name == "Gemini":
            assert request.headers["x-goog-api-key"] == "fixture-GEMINI_API_KEY"
            return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "Review registration."}]}}]})
        assert request.headers["Authorization"].startswith("Bearer fixture-")
        return httpx.Response(200, json={"choices": [{"message": {"content": "Review registration."}}]})

    result = perform(route, lambda client: summarize(client, {
        "verdict": "SUSPICIOUS",
        "target": "private-target.example",
        "evidence": [{"rule_id": "NRD_24H", "detail": "uploaded-email-body"}],
    }))
    assert result["advisory"] == {"source": winner, "text": "Review registration."}
    assert attempted[-1] == winner
    assert all(result["providers"][name] == "Rate limited" for name in attempted[:-1])


def test_ai_disable_respects_configured_keys(keys, monkeypatch):
    monkeypatch.setenv("PHISHMATRIX_AI_SUMMARY", "0")
    outcome = perform(lambda _: pytest.fail("Unexpected network request"),
                      lambda client: summarize(client, {"verdict": "CLEAN", "evidence": []}))
    assert set(outcome["providers"].values()) == {"Sharing disabled"}


def test_urlhaus_queries_exact_public_path_and_keeps_query_local(keys, monkeypatch):
    from app.engines.threat_intel import urlhaus_url

    monkeypatch.setenv("PHISHMATRIX_URLHAUS_PATH_SHARE", "1")
    url = "https://example.com/provider-check"

    def route(request):
        assert str(request.url) == "https://urlhaus-api.abuse.ch/v1/url/"
        assert request.headers["Auth-Key"] == "fixture-ABUSECH_AUTH_KEY"
        return httpx.Response(200, json={"query_status": "ok", "url": url, "url_status": "online"})

    result = perform(route, lambda client: urlhaus_url(client, url))
    assert result == {"status": "Match", "scope": "url"}
    private = perform(lambda _: pytest.fail("Unexpected network request"),
                      lambda client: urlhaus_url(client, url + "?token=private"))
    assert private["status"] == "Query kept local"
