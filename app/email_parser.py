"""Offline email header and MIME body triage."""

import re
from email import policy
from email.parser import Parser
from ipaddress import ip_address
from urllib.parse import unquote, urlsplit

from bs4 import BeautifulSoup

from app.engines.dom_hunter import domain_key, inspect_html
from app.engines.heuristics import lexical_findings
from app.historical_intel import historical_url_lookup
from app.email_content import current_lines, inspect_prose
from app.email_identity import inspect_headers, inspect_name, protected_names
from app.email_policy import EmailEvidence
from app.email_unicode import canonical_text, codepoints, decode_host, rtl_filename_preview
from app.security import defang_ioc, normalize_target, printable

EXECUTABLE_SUFFIXES = {"exe", "scr", "com", "lnk", "bat", "cmd", "msi", "ps1", "vbs", "js", "wsf", "hta", "iso", "html", "htm", "svg"}
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
    return bool(CREDENTIAL_REPLY.match(text.strip()))


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



SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly", "goo.gl", "ow.ly"}
LOGIN_PATH = re.compile(r"/(?:login|sign-?in|verify|webscr|update-password)(?:/|$)", re.I)
LABEL_URL = re.compile(r"(?:https?://)?(?:[\w-]+\.)+[\w-]+(?::\d+)?(?:/\S*)?", re.I)


def inspect_link(ev, raw, brands):
    try:
        url = urlsplit(raw)
        host = url.hostname
        if url.scheme not in {"http", "https"} or not host or len(raw) > 2048:
            return None
    except ValueError:
        return None
    inspect_name(ev, host, "Link hostname", brands, host=True)
    try:
        ip_address(host)
        numeric = True
    except ValueError:
        numeric = False
    login = bool(LOGIN_PATH.search(unquote(url.path)))
    short = domain_key(host) in SHORTENERS
    tld = host.split(".")[-1] in {"xyz", "top", "click", "zip", "tk"}
    features = [name for condition, name in ((numeric, "numeric address"), (short, "shortener"),
                (login, "sign-in path"), (tld, "suffix under review")) if condition]
    if features:
        weight = 18 if login and (numeric or short or tld) else 6 if numeric else 0
        ev.add("EMAIL_URL_STRUCTURE", "Link", raw.split("?")[0].split("#")[0], weight=weight, detail=", ".join(features))
    try:
        target = normalize_target(raw.rstrip(".,"), resolve=False)
    except ValueError:
        return None
    shown = target["url"].split("?", 1)[0].split("#", 1)[0]
    if not target["has_fragment"] and historical_url_lookup(target["url"])["status"] == "Historical match":
        ev.add("EMAIL_ARCHIVED_THREAT", "Local archive", raw.split("?")[0].split("#")[0], weight=10,
               detail="Exact historical URL label. Verify present activity independently.")
    if any(item.rule_id in IMPERSONATION_RULES for item in lexical_findings(target["domain"], target["path"], target["query"])):
        # The same hostname must not earn both lexical and homograph points.
        ev.add("EMAIL_LINK_IMPERSONATION", "Link hostname", host, weight=0 if "EMAIL_HOMOGRAPH" in ev.rows else 28)
    return defang_ioc(shown, target["domain"])["defanged_url"]


def inspect_filename(ev, filename, subject):
    canonical = canonical_text(filename).lower().rstrip(" .")
    extensions = canonical.split(".")
    if len(extensions) >= 2 and extensions[-1] in EXECUTABLE_SUFFIXES:
        double = len(extensions) >= 3 and extensions[-2] in DOCUMENT_SUFFIXES
        ev.add("EMAIL_DOUBLE_EXTENSION" if double else "EMAIL_ACTIVE_ATTACHMENT", "Attachment filename", filename)
    if len(extensions) >= 2 and extensions[-1] in ARCHIVE_SUFFIXES and DOCUMENT_LURE.search(subject) and URGENCY.search(subject):
        ev.add("EMAIL_ARCHIVE_LURE", "Attachment filename", filename)
    if any(c in filename for c in "\u202d\u202e"):
        ev.add("EMAIL_BIDI_FILENAME", "Attachment filename", filename, codepoints=codepoints(filename),
               visual_target=rtl_filename_preview(filename), logical_filename=canonical, detail=f"Directional override in filename. Logical suffix: {extensions[-1][:15]}.")


def html_parts(text, ev, links):
    soup = BeautifulSoup(text, "html.parser")
    for node in soup.select("template, blockquote, .gmail_quote"):
        if node.parent:
            node.decompose()
    page, behaviors = inspect_html(str(soup), include_elements=True)
    for item in behaviors:
        if item.rule_id != "HTML_LINK_MISMATCH":
            ev.add(item.rule_id, "Email HTML", page["matched_elements"][item.rule_id], detail=item.detail)
    for anchor in soup.find_all("a", href=True, limit=100):
        href = str(anchor["href"])
        links.setdefault(href, None)
        label = anchor.get_text(" ", strip=True)
        if len(label) > 300 or not LABEL_URL.fullmatch(label):
            continue
        try:
            shown = urlsplit(label if "://" in label else "//" + label).hostname
            actual = urlsplit(href).hostname
        except ValueError:
            continue
        if actual and shown and domain_key(decode_host(shown)) != domain_key(decode_host(actual)):
            ev.add("EMAIL_LINK_MISMATCH", "Email HTML anchor", label.split("?")[0].split("#")[0],
                   destination_host=actual, detail=f"Displayed host {shown} links to {actual}.")
    for block in soup.find_all(["p", "div", "li", "br"]):
        block.insert_after("\n")
    return soup.get_text(" ", strip=False)


def analyze_raw_email(raw_email: str, *, trusted_authserv_id=None) -> dict:
    # A pasted paragraph beginning with e.g. "Invoice:" is prose unless mail headers follow.
    header_block = re.split(r"\r?\n\r?\n", raw_email.lstrip("\r\n"), maxsplit=1)[0]
    structured = re.search(r"^(?:from|subject|to|date|received|authentication-results|reply-to|return-path|mime-version|content-[\w-]+):", header_block, re.I | re.M)
    msg = Parser(policy=policy.default).parsestr(raw_email if structured else "\n" + raw_email)
    ev = EmailEvidence()
    brands, enterprise = protected_names()
    raw_subject = str(msg.get("Subject", ""))
    prose = [("Subject", raw_subject)]
    attachments, links = [], {}
    for part in message_parts(msg):
        filename = part.get_filename()
        if part.get_content_type() == "message/rfc822":
            attachments.append(printable(filename or "Attached email (.eml)", 120))
            ev.add("EMAIL_ATTACHED_MESSAGE", "MIME type", "message/rfc822")
            continue
        if filename or part.get_content_disposition() == "attachment":
            filename = filename or "Unnamed attachment"
            inspect_filename(ev, filename, canonical_text(raw_subject))
            attachments.append(printable(filename, 120))
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        try:
            if str(part.get("Content-Transfer-Encoding", "")).lower() in {"base64", "quoted-printable"}:
                text = part.get_content()
            else:
                text = part.get_payload()
        except (ValueError, LookupError, UnicodeError):
            continue
        if not isinstance(text, str):
            continue
        if part.get_content_type() == "text/html":
            text = html_parts(text, ev, links)
        else:
            text = "\n".join(current_lines(text))
            links.update(dict.fromkeys(URL_PATTERN.findall(text)[:100]))
        prose.append(("Email body", text))
    shown = [inspect_link(ev, url, brands) for url in list(links)[:100]]
    inspect_prose(ev, prose, bool(attachments), requests_credential_reply, urgent_credential_deadline)
    claims, aligned, verified = inspect_headers(ev, msg, brands, enterprise, trusted_authserv_id)
    mismatch = ev.rows.get("EMAIL_LINK_MISMATCH")
    independent = any(row["points"] >= 18 and row["rule_id"] != "EMAIL_LINK_MISMATCH" for row in ev.rows.values())
    if mismatch and not independent:
        mismatch["points"] = 14
        mismatch["detail"] += " Standalone mismatch may reflect link tracking."
    result = ev.result()
    scope = ("Submitted transport and authentication headers analyzed" if msg.get("Received") and msg.get("Authentication-Results")
             else "Partial headers analyzed (body-only mode)")
    advice = ["Verify sender identity and authentication against receiving-gateway records."]
    if "BEC_BANK_DETAIL_CHANGE" in ev.rows or "BEC_EXECUTIVE_PRESSURE" in ev.rows:
        advice.insert(0, "Hold the payment change and call the vendor or executive using a number already on file.")
    if ev.rows.keys() & {"EMAIL_CREDENTIAL_REPLY", "EMAIL_CREDENTIAL_DEADLINE"}:
        advice.insert(0, "Verify the request through your normal IT portal or help desk.")
    return {**result, "analysis_scope": scope, "subject": printable(raw_subject or "No subject"),
            "from": printable(msg.get("From", "")), "reply_to": printable(msg.get("Reply-To", "")),
            "return_path": printable(msg.get("Return-Path", "")), "authentication_claims": claims,
            "claimed_alignment": aligned, "authentication_verified": bool(verified),
            "extracted_urls": list(dict.fromkeys(url for url in shown if url))[:12], "attachments": attachments[:12],
            "alerts": result["triggers"], "recommendations": advice}
