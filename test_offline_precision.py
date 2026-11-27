"""Regression controls for case scoring, provider failure and downloadable rule semantics."""
import asyncio
from io import BytesIO
import json
import sqlite3
from zipfile import ZipFile

import pytest
import yara
from fastapi.testclient import TestClient
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

from app import orchestrator
from app.email_parser import analyze_raw_email
from app.engines.dom_hunter import inspect_html
from app.engines.heuristics import lexical_findings
from app.engines.rule_pack import PATTERNS, PROFILES
from app.main import app
from app.scoring import RULES, assess

CASES = [
    ("html", '<p>Paste the command in your terminal</p><script>navigator.clipboard.writeText("powershell Get-Date")</script>', False),
    ("html", '<form action="https://idp.example/login"><input type=password disabled></form>', False),
    ("html", '<template><form action="https://idp.example/login"><input type=password></form></template>', False),
    ("html", '<p>Press Win + R to open a file</p><script type="application/json">{"example":"navigator.clipboard.writeText and powershell"}</script>', False),
    ("email", "From: News <news@publisher.org>\nReply-To: replies@helpdesk.net\nReturn-Path: bounce@mailer.com\n\nMonthly news", False),
    ("html", '<form action="/signin"><input type=password></form>', False),
    ("url", ("team-guide.xyz", "/docs/google/account", ""), False),
    ("url", ("training.xyz", "/help", "vendor=google&topic=account"), False),
    ("html", '<form action="https://collector.example/"><input type=password name=p></form>', True),
    ("html", '<form action="https://discord.com/api/webhooks/test"><input type=password></form>', True),
    ("html", '<p>Verify you are human. Press Win + R and paste the command.</p><script>navigator.clipboard.writeText("powershell sample")</script>', True),
    ("email", 'From: test@example.com\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename="invoice.pdf.exe"\n\nfixture', True),
    ("url", ("sbi-kyc-update.xyz", "/verify", ""), True),
    ("email", 'From: test@example.com\nContent-Type: text/html\n\n<form action="https://discord.com/api/webhooks/test"><input type=password></form>', True),
    ("html", '<form method=get action="/login"><input type=password name=p></form>', False),
    ("html", '<form method=post action="/login"><input autocomplete=one-time-code name=otp></form>', False),
    ("html", '<form method=post action="https://collector.example/"><input autocomplete=one-time-code name=otp disabled></form>', False),
    ("html", '<meta http-equiv="refresh" content="1; url=https://other.example/">', False),
    ("html", '<form method=post action="https://collector.example/"><input autocomplete=one-time-code name=otp></form>', True),
    ("html", '<form action="mailto:example@example.org"><input type=password name=p></form>', True),
    ("email", 'From: test@example.com\nSubject: Urgent invoice\nContent-Disposition: attachment; filename="invoice.zip"\n\nfixture', False),
    ("email", 'From: test@example.com\nContent-Disposition: attachment; filename="report\u202Etxt.jpg"\n\nfixture', True),
    ("url", ("paypal-verify.pages.dev", "/", ""), True),
    ("url", ("portal.example", "/login", "redirect=https%3A%2F%2Flogin.example%2F"), False),
]


@pytest.mark.parametrize("kind,value,alert", CASES)
def test_review_decisions(kind, value, alert):
    if kind == "email":
        result = analyze_raw_email(value)
    else:
        evidence = inspect_html(value, "https://portal.example/login")[1] if kind == "html" else lexical_findings(*value)
        result = assess(evidence, coverage_sufficient=False)
    assert (result["verdict"] in {"MALICIOUS", "SUSPICIOUS"}) == alert


def test_offline_api_never_calls_external_sources(monkeypatch):
    async def unexpected(*args):
        pytest.fail("Unexpected external lookup")
    for name in ("lookup_whois_rdap", "query_all_threat_feeds", "summarize"):
        monkeypatch.setattr(orchestrator, name, unexpected)
    monkeypatch.setenv("PHISHMATRIX_DNS_LOOKUPS", "1")
    monkeypatch.setattr("socket.getaddrinfo", unexpected)
    with TestClient(app) as client:
        case = client.post("/api/v1/scan", json={"url": "example.org", "offline": True}).json()
        batch = client.post("/api/v1/bulk-scan", json={"urls": ["example.org"], "offline": True}).json()
    assert case["scan_metadata"]["mode"] == batch["scan_metadata"]["mode"] == "offline"
    assert case["providers"]["RDAP / WHOIS"]["status"] == "Offline"
    assert case["verdict"] == batch["results"][0]["verdict"] == "INCONCLUSIVE"


def test_connectors_can_fail_and_local_case_survives(monkeypatch):
    async def unavailable(*args, **kwargs):
        raise OSError("simulated failure")
    for name in ("lookup_whois_rdap", "query_all_threat_feeds", "summarize"):
        monkeypatch.setattr(orchestrator, name, unavailable)
    case = asyncio.run(orchestrator.investigate_target("https://sbi-kyc-update.xyz/verify"))
    assert case["verdict"] == "SUSPICIOUS"
    assert case["providers"]["External reputation"]["status"] == "Unavailable"
    assert case["siem_event"]["phishmatrix"]["findings"]["BRAND_LURE"]


def test_recent_urlscan_positive_survives_without_exact_negative_coverage(monkeypatch):
    async def providers(*args):
        return {"webrisk": {"status": "Access denied", "scope": "url"},
                "urlscan_malicious": {"status": "Recent malicious scan", "scope": "url"}}

    async def registration(client, domain):
        return orchestrator.unknown_registration(domain)

    monkeypatch.setattr(orchestrator, "query_all_threat_feeds", providers)
    monkeypatch.setattr(orchestrator, "lookup_whois_rdap", registration)
    case = asyncio.run(orchestrator.investigate_target("https://portal.example/review"))
    assert (case["verdict"], case["risk_score"]) == ("SUSPICIOUS", 40)
    assert case["siem_event"]["phishmatrix"]["findings"]["TI_URLSCAN_RECENT"]


@pytest.mark.parametrize("enabled", [False, True])
def test_submit_override_must_be_a_live_submit_control(enabled):
    disabled = "" if enabled else " disabled"
    html = f'<form><input type=password><button{disabled} formaction="https://other.example/in">Continue</button></form>'
    _, findings = inspect_html(html, "https://portal.example/")
    assert ("HTML_SUBMIT_OVERRIDE" in {f.rule_id for f in findings}) == enabled


def test_pack_rules_match_and_reject_controls():
    res = TestClient(app).get("/api/v1/rules/pack.zip")
    assert res.status_code == 200
    archive = ZipFile(BytesIO(res.content))
    manifest = json.loads(archive.read("manifest.json"))
    assert manifest["sigma_rules"] == len(PROFILES) >= 112
    assert manifest["yara_rules"] == len(PATTERNS)
    identities = set()
    for name, _, kind, required in PROFILES:
        assert set(required) <= RULES.keys()
        rule = SigmaCollection.from_yaml(archive.read(f"sigma/{name}.yml").decode())
        assert rule.rules[0].id not in identities
        identities.add(rule.rules[0].id)
        query, = sqliteBackend().convert(rule)
        columns = ["observer.product", "event.action", "phishmatrix.artifact_type", *[f"phishmatrix.findings.{r}" for r in required]]
        with sqlite3.connect(":memory:") as db:
            db.execute("CREATE TABLE logs (" + ", ".join(f'"{c}"' for c in columns) + ")")
            values = ["PhishMatrix", "phishmatrix-triage", kind, *[1 for _ in required]]
            db.execute("INSERT INTO logs VALUES (" + ",".join("?" for _ in columns) + ")", values)
            assert len(db.execute(query).fetchall()) == 1
            for column in columns[3:]:
                db.execute(f'UPDATE logs SET "{column}"=0')
                assert not db.execute(query).fetchall()
                db.execute(f'UPDATE logs SET "{column}"=1')
            db.execute('UPDATE logs SET "phishmatrix.artifact_type" = ?', ("wrong-kind",))
            assert not db.execute(query).fetchall()

    markers = {
        "DiscordCredentialForm": ['<input type=password>', '<form action="https://discord.com/api/webhooks/test">'],
        "TelegramCredentialForm": ['<input type=password>', '<form action="https://api.telegram.org/botfixture">'],
        "CleartextCredentialAction": ['<input type=password>', '<form action="http://example.org/">'],
        "CredentialSubmitOverride": ['<input type=password>', '<button formaction="https://example.org/">'],
        "VerificationClipboard": ["Verify you are human", "Press Win + R", 'navigator.clipboard.writeText("powershell sample")'],
        "DisguisedMailAttachment": ["Content-Disposition: attachment", 'filename="report.pdf.exe"'],
        "CredentialEmailAction": ['<input type=password>', '<form action="mailto:example@example.org">'],
        "CredentialGetMethod": ['<input type=password>', '<form method=get>'],
        "OneTimeCodePost": ['<input autocomplete=one-time-code>', '<form method=post>', '<form action="https://example.org/">'],
        "UrgentInvoiceArchive": ["Subject: Urgent invoice\r\n", "Content-Disposition: attachment", 'filename="invoice.zip"'],
    }
    assert markers.keys() == PATTERNS.keys()
    for name, parts in markers.items():
        matcher = yara.compile(source=archive.read(f"yara/{name}.yar").decode())
        assert matcher.match(data=" ".join(parts).encode())
        for i in range(len(parts)):
            assert not matcher.match(data=" ".join(parts[:i] + parts[i + 1:]).encode())
