from base64 import b64decode
from email.message import EmailMessage

import idna
import pytest
from fastapi.testclient import TestClient
from app.email_parser import analyze_raw_email
from app.email_policy import BOUNDS
from app.email_unicode import decode_host, normalized_distance, scripts, skeleton
from app.main import app

BANK = "Please process payment by NEFT using our revised bank details."
PRESSURE = "Urgent. We need to clear the dispatch hold within 2 hours."
FRAUD = f"From: Accounts Payable <desk@gmail.com>\nSubject: Remittance\n\n{BANK}\n{PRESSURE}"
PORTAL = ('From: IT Support <desk@corp-security-update.example>\nContent-Type: text/html\n\n'
          '<p>Please enter your password.</p><a href="https://gateway.example/verify">portal.example</a>')


def rows(case):
    return {row["rule_id"]: row for row in case["evidence"]}


@pytest.mark.parametrize("text", [
    "Urgent: the finance meeting has moved.",
    "Invoice: please process payment by NEFT under the existing terms.",
    "The attached invoice covers March. Thank you.",
    "We have not changed our bank details.",
    "Never process payment to a new bank account by email.",
    "The new bank holiday calendar is available.",
    "The revised invoice has the corrected tax rate.",
    "प्रिय ग्राहक, आपका चालान संलग्न है।",
    "Здравствуйте, во вложении счёт за октябрь.",
    "مرحباً، يرجى مراجعة الفاتورة المرفقة.",
    "From: रमेश शर्मा <office@example.org>\n\nहमारा कार्य\u200dक्रम आज है।",
    "From: Мария <maria@пример.рф>\n\nДо встречи.",
    "From: HR <sarah@gmail.com>\n\nThe picnic starts at noon.",
    "Read https://bücher.de/login for account access.",
    "From: it@example.org\n\nHi.\nOn Mon Pat wrote:\n" + BANK,
    "Content-Type: text/html\n\n<blockquote>" + BANK + "</blockquote>",
])
def test_normal_mail_stays_below_alert(text):
    case = analyze_raw_email(text)
    assert case["verdict"] == "LOW_RISK", case["evidence"]
    assert "EMAIL_HOMOGRAPH" not in rows(case)


@pytest.mark.parametrize(("text", "score", "verdict"), [
    (BANK, 35, "SUSPICIOUS"),
    (BANK + "\n" + PRESSURE, 53, "LIKELY_PHISHING"),
    (FRAUD, 89, "HIGH_CONFIDENCE_PHISHING"),
    ("Urgent. Please initiate a wire transfer.", 28, "SUSPICIOUS"),
    ("Please reply with your OTP.", 35, "SUSPICIOUS"),
])
def test_text_only_scores(text, score, verdict):
    result = analyze_raw_email(text)
    assert (result["risk_score"], result["verdict"]) == (score, verdict)
    assert result["analysis_scope"] == "Partial headers analyzed (body-only mode)"
    assert result["extracted_urls"] == []


@pytest.mark.parametrize("value", ["pаypal", "аррӏе", "mіcrosoft", "ｍicrosoft", "micros0ft", "rnicrosoft", "pαypal", "𝐩aypal"])
def test_protected_skeletons(value):
    r = analyze_raw_email(f"From: desk@{value}.example\n\nHello")
    row = rows(r)["EMAIL_HOMOGRAPH"]
    assert (row["severity"], row["score_contribution"]) == ("CRITICAL", 45)
    assert row["visual_target"] in {"paypal", "apple", "microsoft"}
    if not value.isascii():
        assert row["codepoints"]


@pytest.mark.parametrize("source", ["From: Desk <test@{}>", "Reply-To: desk@{}", "From: pаypal <desk@example.org>\nX-Test: {}", "\nhttps://{}/login"])
def test_header_display_or_url_homograph(source):
    puny = idna.encode("pаypal.com").decode()
    raw = source.format(puny) + "\n\nReport"
    r = rows(analyze_raw_email(raw))["EMAIL_HOMOGRAPH"]
    assert "CYRILLIC SMALL LETTER A (U+0430)" in r["codepoints"]
    assert r["visual_target"] == "paypal"
    assert decode_host(puny) == "pаypal.com"


def test_internal_domain_and_transposition(monkeypatch):
    monkeypatch.setenv("PHISHMATRIX_ENTERPRISE_DOMAINS", "northstar.example")
    assert "EMAIL_HOMOGRAPH" in rows(analyze_raw_email("From: hi@nоrthstar.example\n\nHi"))
    assert "EMAIL_TYPO_DOMAIN" in rows(analyze_raw_email("From: hi@northsatr.example\n\nHi"))
    assert normalized_distance("northsatr", "northstar") == pytest.approx(1 / 9)
    assert skeleton("pаypal") == skeleton("paypal")
    assert scripts("pаypal") == {"LATIN", "CYRILLIC"}


def test_invisible_payment_language_and_financial_code():
    raw = "Please process payment by N\u200bE\u200cF\u200dT to our re\u00advised bank details. IFSC: АBCD0123456"
    r = rows(analyze_raw_email(raw))
    assert {"BEC_BANK_DETAIL_CHANGE", "EMAIL_HIDDEN_KEYWORD", "EMAIL_CODE_SPOOF"} <= r.keys()
    assert "U+200B" in str(r["EMAIL_HIDDEN_KEYWORD"]["codepoints"])
    assert r["EMAIL_HIDDEN_KEYWORD"]["matched_evidence"] in raw


@pytest.mark.parametrize("ext", ["exe","js","vbs","iso","html","htm","svg","lnk"])
def test_attachment_extensions(ext):
    m = EmailMessage()
    m.set_content("Invoice attached")
    m.add_attachment(b"fixture", maintype="application", subtype="octet-stream", filename=f"invoice.pdf.{ext}")
    row = rows(analyze_raw_email(m.as_string()))["EMAIL_DOUBLE_EXTENSION"]
    assert row["matched_evidence"] == f"invoice.pdf.{ext}"


def test_rtl_filename_and_missing_mandate_attachment():
    m = EmailMessage()
    m.set_content(BANK + " See the attached mandate letter.")
    assert "BEC_MISSING_MANDATE" in rows(analyze_raw_email(m.as_string()))
    m.add_attachment(b"fixture", maintype="application", subtype="octet-stream", filename="payment\u202efdp.exe")
    r = rows(analyze_raw_email(m.as_string()))
    assert "BEC_MISSING_MANDATE" not in r
    assert "RIGHT-TO-LEFT OVERRIDE (U+202E)" in r["EMAIL_BIDI_FILENAME"]["codepoints"]
    assert r["EMAIL_BIDI_FILENAME"]["visual_target"].endswith(".pdf")
    assert r["EMAIL_BIDI_FILENAME"]["logical_filename"].endswith(".exe")


def test_auth_results_esp_and_trust_boundary(monkeypatch):
    monkeypatch.setenv("PHISHMATRIX_ENTERPRISE_DOMAINS", "vendor.example")
    header = ("From: Accounts Payable <pay@vendor.example>\nReturn-Path: bounce@sendgrid.net\n"
              "Received: from transport.example\nList-Unsubscribe: <mailto:off@vendor.example>\n"
              "Authentication-Results: mx.example; dkim=pass header.d=vendor.example; "
              "spf=pass smtp.mailfrom=pay@vendor.example; dmarc=pass header.from=vendor.example\n\n")
    r = analyze_raw_email(header + "Here is your monthly invoice.")
    assert r["risk_score"] == 0 and not r["authentication_verified"]
    assert "EMAIL_ENVELOPE" not in rows(r)
    r = analyze_raw_email(header + BANK)
    assert not r["authentication_verified"] and "BEC_BANK_DETAIL_CHANGE" in rows(r)
    trusted = analyze_raw_email(header + BANK, trusted_authserv_id="mx.example")
    assert trusted["authentication_verified"] and "EMAIL_ENVELOPE" not in rows(trusted)
    assert trusted["risk_score"] >= 35


@pytest.mark.parametrize("clause", ["spf=fail", "spf=softfail", "dkim=fail", "dmarc=fail"])
def test_header_failure_with_reply_and_fraud(clause):
    raw = f"From: billing@vendor.example\nReply-To: payment@other.example\nAuthentication-Results: receiver.example; {clause}\n\n{BANK}"
    r = rows(analyze_raw_email(raw))
    assert r["EMAIL_ROUTE_RISK"]["severity"] == "HIGH"
    assert r["EMAIL_REPLY_TO"]["matched_evidence"] == "payment@other.example"
    assert clause in r["EMAIL_AUTH_CLAIM"]["matched_evidence"]


def test_credential_harvesting_api_reports_and_contributions():
    c = TestClient(app)
    result = c.post("/api/v1/email-scan", json={"raw_email": PORTAL, "include_pdf": True}).json()
    ev = rows(result)
    assert {"EMAIL_LINK_MISMATCH", "EMAIL_CREDENTIAL_PORTAL", "EMAIL_ROLE_DOMAIN"} <= ev.keys()
    assert result["verdict"] == "HIGH_CONFIDENCE_PHISHING"
    assert b64decode(result["report_pdf"]).startswith(b"%PDF")
    assert result["siem_event"]["event"]["kind"] == "alert"
    for row in ev.values():
        assert row["matched_evidence"] and row["false_positive_note"] and row["severity"]
    assert sum(row["score_contribution"] for row in ev.values()) == result["risk_score"] <= 100


@pytest.mark.parametrize("value,features", [
    ("https://192.0.2.20/login", "numeric address"), ("https://tinyurl.com/docs", "shortener"),
    ("https://portal.click/webscr", "suffix"), ("https://portal.tk/update-password", "sign-in path"),
])
def test_link_structure(value, features):
    row = rows(analyze_raw_email(value))["EMAIL_URL_STRUCTURE"]
    assert features in row["detail"]


def test_thresholds_and_cap():
    for n, label in [(0,"LOW_RISK"),(19,"LOW_RISK"),(20,"SUSPICIOUS"),(49,"SUSPICIOUS"),
                     (50,"LIKELY_PHISHING"),(79,"LIKELY_PHISHING"),(80,"HIGH_CONFIDENCE_PHISHING"),(100,"HIGH_CONFIDENCE_PHISHING")]:
        assert next(v for floor, v in BOUNDS if n >= floor) == label
    case = analyze_raw_email(FRAUD + "\nSee the attached mandate letter. https://pаypal.com/login")
    assert case["risk_score"] == sum(x["score_contribution"] for x in case["evidence"]) == 100
