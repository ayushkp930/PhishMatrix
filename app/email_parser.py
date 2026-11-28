"""Offline email header and MIME body triage."""

import re
from email import policy
from email.parser import Parser
from email.utils import parseaddr

from bs4 import BeautifulSoup

from app.engines.dom_hunter import domain_key, inspect_html
from app.engines.heuristics import lexical_findings
from app.historical_intel import historical_url_lookup
from app.scoring import assess, finding
from app.security import defang_ioc, normalize_target, printable

EXECUTABLE_SUFFIXES = {"exe", "scr", "com", "lnk", "bat", "cmd", "msi", "ps1", "vbs", "js", "wsf", "hta"}
DOCUMENT_SUFFIXES = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png"}
URL_PATTERN = re.compile(r"https?://[^\s'\"<>)\]]+", re.I)
ARCHIVE_SUFFIXES = {"zip", "rar", "7z", "iso", "img"}
DOCUMENT_LURE = re.compile(r"\b(?:invoice|payment|payroll|statement|receipt)\b", re.I)
URGENCY = re.compile(r"\b(?:urgent|immediate|overdue|today|past due)\b", re.I)
IMPERSONATION_RULES = {"BRAND_CONFUSABLE", "URL_BRAND_SUBDOMAIN", "URL_SHARED_TENANT_LURE"}
CREDENTIAL_EXPIRY = re.compile(
    r"\b(?:password|passcode)s?\s+(?:(?:will|is about to)\s+)?expir(?:e|es|ing)\b"
    r"|\baccount\s+will\s+be\s+(?:suspended|disabled|locked)\b", re.I,
)
ACTION_PRESSURE = re.compile(r"\b(?:urgent|action required|act now|immediate action|final notice)\b", re.I)
SHORT_DEADLINE = re.compile(r"\b(?:in|within)\s+(?:the next\s+)?(\d{1,3})\s*(hours?|hrs?|minutes?|mins?)\b", re.I)
CREDENTIAL_REPLY = re.compile(
    r"^(?:please\s+)?(?:reply\s+(?:to (?:this (?:email|message)|us)\s+)?with|send\s+us|email\s+us)"
    r"\s+your\s+(?:(?:current|login)\s+)?(?:password|one[- ]time (?:pass)?code|otp|verification code)"
    r"(?=\s*(?:$|[.!?,;]|(?:to|for|within)\b))", re.I,
)


def urgent_credential_deadline(text):
    if not CREDENTIAL_EXPIRY.search(text) or not ACTION_PRESSURE.search(text):
        return False
    return any(0 < int(value) <= (12 if unit.lower().startswith("h") else 720)
               for value, unit in SHORT_DEADLINE.findall(text))


def requests_credential_reply(text):
    for line in text.splitlines():
        line = line.strip()
        if re.fullmatch(r"(?:on .+ wrote:|-+\s*(?:forwarded message|original message)\s*-+)", line, re.I):
            break
        if not line.startswith(">") and CREDENTIAL_REPLY.match(line):
            return True
    return False


def message_parts(message):
    stack = [message]
    for _ in range(50):
        if not stack:
            break
        part = stack.pop()
        yield part
        if (part.get_content_maintype() == "multipart" and part.is_multipart()
                and not part.get_filename() and part.get_content_disposition() != "attachment"):
            stack.extend(reversed(part.get_payload()))


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

    links = {}
    display_mismatches = 0
    embedded_behaviors = set()
    credential_deadline = urgent_credential_deadline(subject)
    credential_reply = False
    attachments = []
    attachment_rules = set()
    for part in message_parts(msg):
        if part.get_content_type() == "message/rfc822":
            attachments.append(printable(part.get_filename() or "Attached email (.eml)", 120))
            attachment_rules.add("EMAIL_ATTACHED_MESSAGE")
            continue
        if part.get_filename() or part.get_content_disposition() == "attachment":
            filename = part.get_filename() or "Unnamed attachment"
            if len(filename) <= 1024:
                extensions = filename.lower().rstrip(" .").split(".")
                if len(extensions) >= 2 and extensions[-1] in EXECUTABLE_SUFFIXES:
                    double = len(extensions) >= 3 and extensions[-2] in DOCUMENT_SUFFIXES
                    attachment_rules.add("EMAIL_DOUBLE_EXTENSION" if double else "EMAIL_ACTIVE_ATTACHMENT")
                if len(extensions) >= 2 and extensions[-1] in ARCHIVE_SUFFIXES and DOCUMENT_LURE.search(subject) and URGENCY.search(subject):
                    attachment_rules.add("EMAIL_ARCHIVE_LURE")
                if any(control in filename for control in "\u202d\u202e"):
                    attachment_rules.add("EMAIL_BIDI_FILENAME")
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
            for template in soup.find_all("template"):
                template.extract()
            for anchor in soup.find_all("a", href=True, limit=50):
                links.setdefault(str(anchor["href"]), None)
            for quote in soup.find_all("blockquote"):
                quote.extract()
            prose = "\n".join(block.get_text(" ", strip=True) for block in soup.find_all(["p", "li"])) or soup.get_text(" ", strip=True)
        else:
            links.update(dict.fromkeys(URL_PATTERN.findall(text)[:50]))
            prose = text
        credential_reply = credential_reply or requests_credential_reply(prose)

    safe_links = []
    link_rules = set()
    for candidate in list(links)[:100]:
        if not candidate.lower().startswith(("http://", "https://")):
            continue
        try:
            target = normalize_target(candidate.rstrip(".,"), resolve=False)
        except ValueError:
            continue
        safe_url = target["url"].split("?", 1)[0]
        if len(safe_links) < 12:
            shown = defang_ioc(safe_url, target["domain"])["defanged_url"]
            if shown not in safe_links:
                safe_links.append(shown)
        if not target["has_fragment"] and historical_url_lookup(target["url"])["status"] == "Historical match":
            link_rules.add("EMAIL_ARCHIVED_THREAT")
        if any(item.rule_id in IMPERSONATION_RULES for item in lexical_findings(target["domain"], target["path"], target["query"])):
            link_rules.add("EMAIL_LINK_IMPERSONATION")

    findings = [
        finding(rule, "Submitted email", "Matched attachment filename metadata. File contents were not opened.")
        for rule in sorted(attachment_rules)
    ]
    findings.extend(finding(rule, "Submitted email HTML", "Observed in the inert HTML MIME body.") for rule in sorted(embedded_behaviors))
    if credential_deadline:
        findings.append(finding("EMAIL_CREDENTIAL_DEADLINE", "Email subject",
                                "The subject combines a short deadline, an account or credential warning, and pressure to act."))
    if credential_reply:
        findings.append(finding("EMAIL_CREDENTIAL_REPLY", "Email body",
                                "The message directly asks the recipient to disclose a password or code in a reply or email."))
    if "EMAIL_ARCHIVED_THREAT" in link_rules:
        findings.append(finding("EMAIL_ARCHIVED_THREAT", "Local archive", "An exact email link matches a historical phishing, malware or defacement label. Current activity is unverified."))
    if "EMAIL_LINK_IMPERSONATION" in link_rules:
        findings.append(finding("EMAIL_LINK_IMPERSONATION", "Submitted email link", "At least one linked hostname resembles or impersonates a monitored brand."))
    if from_domain and reply_domain and from_domain != reply_domain:
        findings.append(finding("EMAIL_REPLY_TO", "Submitted email", f"Sender domain {from_domain} differs from Reply-To domain {reply_domain}."))
        if display_mismatches or link_rules:
            findings.append(finding("EMAIL_REPLY_TO_CORROBORATED", "Submitted email", "A different reply domain appears alongside a deceptive or listed link."))
    if from_domain and envelope_domain and from_domain != envelope_domain:
        findings.append(finding("EMAIL_ENVELOPE", "Submitted email", "Different return paths can also be legitimate for mailing services."))
    if display_mismatches:
        findings.append(finding("EMAIL_LINK_MISMATCH", "Submitted email", f"{display_mismatches} link label(s) differ from their destination."))
    if any(token.lower() in {"fail", "softfail"} for values in claims.values() for token in values):
        findings.append(finding("EMAIL_AUTH_CLAIM", "Submitted header", "Verify this claim in your trusted mail-gateway logs."))
    result = assess(findings, coverage_sufficient=False)
    recommendations = ["Verify sender authentication in gateway logs and review links in an approved isolation environment."]
    if credential_deadline or credential_reply:
        recommendations.insert(0, "Verify any password or account deadline independently through your usual IT portal or help desk.")
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
        "recommendations": recommendations,
    }
