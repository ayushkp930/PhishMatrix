"""Offline email header and MIME body triage."""

import re
from email import policy
from email.parser import Parser
from email.utils import parseaddr

from bs4 import BeautifulSoup

from app.engines.dom_hunter import domain_key, inspect_html
from app.scoring import assess, finding
from app.security import defang_ioc, normalize_target, printable

EXECUTABLE_SUFFIXES = {"exe", "scr", "com", "lnk", "bat", "cmd", "msi", "ps1", "vbs", "js", "wsf", "hta"}
DOCUMENT_SUFFIXES = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png"}
URL_PATTERN = re.compile(r"https?://[^\s'\"<>)\]]+", re.I)


def extract_address(msg, field: str) -> tuple[str, str]:
    header = str(msg.get(field, ""))
    _, address = parseaddr(header)
    return printable(header), domain_key(address.rsplit("@", 1)[-1]) if "@" in address else ""


def analyze_raw_email(raw_email: str) -> dict:
    msg = Parser(policy=policy.default).parsestr(raw_email)
    sender, from_domain = extract_address(msg, "From")
    return_path, envelope_domain = extract_address(msg, "Return-Path")
    reply_to, reply_domain = extract_address(msg, "Reply-To")
    subject = printable(msg.get("Subject") or "No subject")
    auth = " ".join(str(value) for value in msg.get_all("Authentication-Results", []))
    claims = {key: re.findall(rf"\b{key}\s*=\s*([a-z]+)", auth, re.I)[:6] for key in ("spf", "dkim", "dmarc")}

    links = set()
    display_mismatches = 0
    embedded_behaviors = set()
    attachments = []
    attachment_rules = set()
    for part in list(msg.walk())[:50]:
        if part.get_filename() or part.get_content_disposition() == "attachment":
            filename = part.get_filename() or "Unnamed attachment"
            if len(filename) <= 1024:
                extensions = filename.lower().rstrip(" .").split(".")
                if len(extensions) >= 2 and extensions[-1] in EXECUTABLE_SUFFIXES:
                    double = len(extensions) >= 3 and extensions[-2] in DOCUMENT_SUFFIXES
                    attachment_rules.add("EMAIL_DOUBLE_EXTENSION" if double else "EMAIL_ACTIVE_ATTACHMENT")
            attachments.append(printable(filename, 120))
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        try:
            text = part.get_content()
        except (LookupError, UnicodeError, ValueError):
            continue
        if not isinstance(text, str):
            continue
        if part.get_content_type() == "text/html":
            soup = BeautifulSoup(text, "html.parser")
            page, behaviors = inspect_html(text)
            display_mismatches += page["link_mismatches"]
            embedded_behaviors.update(item.rule_id for item in behaviors if item.rule_id != "HTML_LINK_MISMATCH")
            links.update(str(a["href"]) for a in soup.find_all("a", href=True, limit=50))
        else:
            links.update(URL_PATTERN.findall(text)[:50])
        if len(links) >= 100:
            break

    safe_links = []
    for candidate in sorted(links)[:100]:
        if not candidate.lower().startswith(("http://", "https://")):
            continue
        try:
            target = normalize_target(candidate.rstrip(".,"), resolve=False)
        except ValueError:
            continue
        safe_url = target["url"].split("?", 1)[0]
        safe_links.append(defang_ioc(safe_url, target["domain"])["defanged_url"])
        if len(safe_links) == 12:
            break

    findings = [
        finding(rule, "Submitted email", "Matched attachment filename metadata. File contents were not opened.")
        for rule in sorted(attachment_rules)
    ]
    findings.extend(finding(rule, "Submitted email HTML", "Observed in the inert HTML MIME body.") for rule in sorted(embedded_behaviors))
    if from_domain and reply_domain and from_domain != reply_domain:
        findings.append(finding("EMAIL_REPLY_TO", "Submitted email", f"Sender domain {from_domain} differs from Reply-To domain {reply_domain}."))
    if from_domain and envelope_domain and from_domain != envelope_domain:
        findings.append(finding("EMAIL_ENVELOPE", "Submitted email", "Different return paths can also be legitimate for mailing services."))
    if display_mismatches:
        findings.append(finding("EMAIL_LINK_MISMATCH", "Submitted email", f"{display_mismatches} link label(s) differ from their destination."))
    if any(token.lower() in {"fail", "softfail"} for values in claims.values() for token in values):
        findings.append(finding("EMAIL_AUTH_CLAIM", "Submitted header", "Verify this claim in your trusted mail-gateway logs."))
    result = assess(findings, coverage_sufficient=False)
    return {
        **result,
        "email_risk_score": result["risk_score"],
        "subject": subject,
        "from": sender,
        "return_path": return_path,
        "reply_to": reply_to,
        "authentication_claims": claims,
        "authentication_verified": False,
        "extracted_urls": list(dict.fromkeys(safe_links)),
        "attachments": attachments[:12],
        "alerts": result["triggers"],
        "recommendations": ["Verify sender authentication in gateway logs and review links in an approved isolation environment."],
    }
