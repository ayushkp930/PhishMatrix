"""Regression controls for case scoring, provider failure and downloadable rule semantics."""
import asyncio
from io import BytesIO
import json
import sqlite3
from zipfile import ZipFile
from base64 import b64decode

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
    assert (result["verdict"] in {"MALICIOUS", "SUSPICIOUS", "LIKELY_PHISHING", "HIGH_CONFIDENCE_PHISHING"}) == alert


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


def test_newsletter_reply_routing_and_attached_email_stay_context_only():
    raw = ('From: news@publisher.org\nReply-To: replies@mailer.org\nMIME-Version: 1.0\n'
           'Content-Type: multipart/mixed; boundary=sample\n\n'
           '--sample\nContent-Type: text/plain\n\nNewsletter\n'
           '--sample\nContent-Type: message/rfc822\nContent-Disposition: attachment; filename=example.eml\n\n'
           'From: sender@example.org\nContent-Type: text/html\n\n'
           '<a href="https://collector.example/">https://publisher.org/</a>\n--sample--')
    result = analyze_raw_email(raw)
    assert result["risk_score"] == 0
    assert not result["extracted_urls"]
    assert {item["rule_id"] for item in result["evidence"]} == {"EMAIL_REPLY_TO", "EMAIL_ATTACHED_MESSAGE"}


def test_email_archive_alone_with_routine_reply_routing_stays_low(monkeypatch):
    def history(url):
        return {"status": "Historical match" if url == "https://collector.example/record" else "No historical match"}

    monkeypatch.setattr("app.email_parser.historical_url_lookup", history)
    raw = "From: alerts@example.org\nReply-To: reply@collector.example\n\nhttps://collector.example/record"
    result = analyze_raw_email(raw)
    assert (result["verdict"], result["risk_score"]) == ("LOW_RISK", 10)
    assert any(item["rule_id"] == "EMAIL_ARCHIVED_THREAT" for item in result["evidence"])
    assert analyze_raw_email(raw + "#another-page")["risk_score"] == 0


def test_email_report_is_opt_in_and_keeps_raw_message_out():
    text = "From: alerts@example.org\nSubject: Review <b>plain</b>\n\nPrivate body marker"
    with TestClient(app) as client:
        plain = client.post("/api/v1/email-scan", json={"raw_email": text}).json()
        response = client.post("/api/v1/email-scan", json={"raw_email": text, "include_pdf": True})
    assert response.status_code == 200
    assert "report_pdf" not in plain
    assert "Private body marker" not in response.text
    assert b64decode(response.json()["report_pdf"], validate=True).startswith(b"%PDF-")


@pytest.mark.parametrize(("subject", "score"), [
    ("URGENT: Action Required - Your Email Password Expires in 2 Hours", 20),
    ("Password expires in 2 days", 0),
    ("Password expires in 2 hours", 0),
    ("URGENT: Your meeting starts in 2 hours", 0),
    ("Final notice: your account will be suspended within 30 minutes", 20),
])
def test_credential_deadline_correlates_with_role_and_sender_domain(subject, score):
    raw = f"From: IT Support Desk <support@corp-security-update.com>\nSubject: {subject}\n\nReminder."
    result = analyze_raw_email(raw)
    assert (result["verdict"], result["risk_score"]) == (("SUSPICIOUS", 44) if score else ("LOW_RISK", 0))
    assert ("EMAIL_CREDENTIAL_DEADLINE" in {r["rule_id"] for r in result["evidence"]}) == bool(score)


@pytest.mark.parametrize(("mime", "body", "matched"), [
    ("text/plain", "Please reply to this email with your one-time code.", True),
    ("text/plain", "Never reply with your password.", False),
    ("text/plain", "Please send us your password reset request.", False),
    ("text/plain", "Previous message follows.\nOn Wednesday Dana wrote:\nReply with your password.", False),
    ("text/html", "<p>Send us your password.</p>", True),
    ("text/html", "<blockquote><p>Send us your password.</p></blockquote>", False),
])
def test_credential_reply_requires_a_direct_unquoted_request(mime, body, matched):
    result = analyze_raw_email(f"From: notice@example.org\nContent-Type: {mime}\n\n{body}")
    assert result["risk_score"] == (35 if matched else 0)


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
