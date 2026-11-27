"""Downloadable, versioned hunts. Raw-text YARA matches are triage leads only."""
import json
from functools import lru_cache
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile
from itertools import product

from app.engines.soc_generator import sigma
from app.scoring import RULES, VERSION

# The generated Sigma rules query the boolean fields in exported case events.
CURATED_PROFILES = (
    ("page_webhook", "HTML password form targeting a messaging endpoint", "html", ("HTML_WEBHOOK_FORM",)),
    ("email_webhook", "Messaging endpoint in an email credential form", "email", ("HTML_WEBHOOK_FORM",)),
    ("page_clipboard", "Verification prompt with clipboard shell instructions", "html", ("HTML_CLIPBOARD_EXEC",)),
    ("email_clipboard", "Clipboard verification instructions in an email body", "email", ("HTML_CLIPBOARD_EXEC",)),
    ("submit_override", "Credential submit control routes to another site", "html", ("HTML_SUBMIT_OVERRIDE",)),
    ("credential_deception", "Foreign credential destination and deceptive link", "html", ("HTML_CROSS_ORIGIN_FORM", "HTML_LINK_MISMATCH")),
    ("base_cleartext", "Base tag redirects credentials over HTTP", "html", ("HTML_CREDENTIAL_FORM_REDIRECT", "HTML_INSECURE_PASSWORD")),
    ("attachment_reply", "Disguised attachment with an external reply route", "email", ("EMAIL_DOUBLE_EXTENSION", "EMAIL_REPLY_TO")),
    ("attachment_link", "Executable attachment with deceptive link", "email", ("EMAIL_ACTIVE_ATTACHMENT", "EMAIL_LINK_MISMATCH")),
    ("new_confusable", "Newly registered confusable domain", "url", ("NRD_24H", "BRAND_CONFUSABLE")),
    ("brand_reputation", "Brand lure corroborated by domain intelligence", "url", ("BRAND_LURE", "TI_DOMAIN")),
    ("historical_current", "Archived URL corroborated by a current exact match", "url", ("TI_HISTORICAL_URL", "TI_URL_EXACT")),
)

# Correlations combine observed behaviors with a second triage signal.
URL_STRUCTURE = (
    "BRAND_CONFUSABLE", "BRAND_LOOKALIKE", "BRAND_LURE", "URL_BRAND_SUBDOMAIN", "URL_IP_LOGIN",
    "URL_SHARED_TENANT_LURE", "URL_OFFSITE_REDIRECT", "RISKY_SUFFIX", "HOSTED_TENANT",
)
URL_REPUTATION = ("TI_URL_EXACT", "TI_URLSCAN_RECENT", "TI_HISTORICAL_URL", "TI_DOMAIN", "TI_IP")
REGISTRATION = ("NRD_24H", "NRD_30D")
PAGE_CREDENTIALS = (
    "HTML_CROSS_ORIGIN_FORM", "HTML_SUBMIT_OVERRIDE", "HTML_WEBHOOK_FORM",
    "HTML_CREDENTIAL_FORM_REDIRECT", "HTML_PASSWORD_MAILTO", "HTML_OTP_CROSS_ORIGIN",
)
PAGE_CONTEXT = ("HTML_LINK_MISMATCH", "HTML_PASSWORD_QUERY", "HTML_INSECURE_PASSWORD", "HTML_EXTERNAL_REFRESH")
EMAIL_BEHAVIORS = (
    "HTML_WEBHOOK_FORM", "HTML_PASSWORD_QUERY", "HTML_PASSWORD_MAILTO", "HTML_INSECURE_PASSWORD", "HTML_CLIPBOARD_EXEC",
)
EMAIL_ATTACHMENTS = ("EMAIL_DOUBLE_EXTENSION", "EMAIL_ACTIVE_ATTACHMENT", "EMAIL_ARCHIVE_LURE", "EMAIL_BIDI_FILENAME")
EMAIL_CONTEXT = ("EMAIL_REPLY_TO", "EMAIL_LINK_MISMATCH", "EMAIL_AUTH_CLAIM")


def correlation_profiles():
    seen = {(kind, frozenset(required)) for _, _, kind, required in CURATED_PROFILES}
    groups = (
        ("url", product(URL_STRUCTURE, (*REGISTRATION, *URL_REPUTATION))),
        ("url", product(REGISTRATION, (*URL_REPUTATION, "TI_HISTORICAL_CONFLICT"))),
        ("html", product(PAGE_CREDENTIALS, PAGE_CONTEXT)),
        ("html", product(("HTML_CLIPBOARD_EXEC",), PAGE_CONTEXT)),
        ("email", product(EMAIL_ATTACHMENTS, (*EMAIL_CONTEXT, *EMAIL_BEHAVIORS))),
        ("email", product(EMAIL_BEHAVIORS, EMAIL_CONTEXT)),
    )
    for kind, pairs in groups:
        for left, right in pairs:
            # Numeric URLs carry no registrable-domain age, brand label or hosting suffix.
            if ((left == "URL_IP_LOGIN" and right in {*REGISTRATION, "TI_DOMAIN"})
                    or (left == "HOSTED_TENANT" and right in REGISTRATION)):
                continue
            signature = (kind, frozenset((left, right)))
            if signature in seen:
                continue
            seen.add(signature)
            name = f"{kind}_{left.lower()}_{right.lower()}"
            title = f"{RULES[left][0]} with {RULES[right][0].lower()}"
            yield name, title, kind, (left, right)


PROFILES = (*CURATED_PROFILES, *correlation_profiles())

# Require groups of markers. These text hunts cannot resolve DOM relationships or MIME decoding.
PASSWORD = r"""<input\b[^>]{0,240}\btype\s*=\s*["']?password\b"""
FORM_ACTION = r"""<form\b[^>]{0,256}\baction\s*=\s*["']?"""
PATTERNS = {
    "DiscordCredentialForm": (PASSWORD, FORM_ACTION + r"https:\/\/(www\.)?discord(app)?\.com\/api\/webhooks\/"),
    "TelegramCredentialForm": (PASSWORD, FORM_ACTION + r"https:\/\/api\.telegram\.org\/bot"),
    "CleartextCredentialAction": (PASSWORD, FORM_ACTION + r"http:\/\/"),
    "CredentialSubmitOverride": (PASSWORD, r"""<(button|input)\b[^>]{0,240}\bformaction\s*=\s*["']?https?:\/\/"""),
    "VerificationClipboard": (r"verify (that )?you are human|human verification|captcha", r"win(dows)?\s*\+\s*r|paste the command",
                              r"""navigator\.clipboard\.writeText\s*\(\s*["']\s*(powershell|pwsh|mshta|cmd)(\.exe)?\s"""),
    "DisguisedMailAttachment": (r"Content-Disposition:\s*attachment", r"""filename\s*=\s*["']?[^\r\n";]{1,100}\.(pdf|docx?|xlsx?)\.(exe|scr|lnk|js|vbs)\b"""),
    "CredentialEmailAction": (PASSWORD, FORM_ACTION + r"mailto:"),
    "CredentialGetMethod": (PASSWORD, r"""<form\b[^>]{0,256}\bmethod\s*=\s*["']?get\b"""),
    "OneTimeCodePost": (r"""<input\b[^>]{0,240}\bautocomplete\s*=\s*["']?one-time-code\b""",
                        r"""<form\b[^>]{0,256}\bmethod\s*=\s*["']?post\b""", FORM_ACTION + r"https?:\/\/"),
    "UrgentInvoiceArchive": (r"Subject:[^\r\n]{0,140}(urgent|overdue)[^\r\n]{0,140}(invoice|payment)",
                             r"Content-Disposition:\s*attachment",
                             r"""filename\s*=\s*["']?[^\r\n";]{1,100}\.(zip|rar|7z|iso)\b"""),
}


@lru_cache(maxsize=1)
def build_pack() -> bytes:
    stream = BytesIO()
    with ZipFile(stream, "w", compression=ZIP_DEFLATED) as archive:
        for name, title, kind, required in PROFILES:
            fields = {"observer.product": "PhishMatrix", "event.action": "phishmatrix-triage", "phishmatrix.artifact_type": kind}
            fields.update({f"phishmatrix.findings.{key}": True for key in required})
            archive.writestr(f"sigma/{name}.yml", sigma(title, "Requires structured PhishMatrix case events. Review correlated evidence before escalation.",
                                                       {"product": "phishmatrix"}, fields, level="low"))
        for name, patterns in PATTERNS.items():
            strings = "\n".join(f"        $s{i} = /{pattern}/ nocase" for i, pattern in enumerate(patterns))
            archive.writestr(f"yara/{name}.yar", f'rule PM_{name} {{\n    meta:\n        purpose = "Raw text triage"\n'
                             f'    strings:\n{strings}\n    condition:\n        filesize <= 1MB and all of them\n}}\n')
        archive.writestr("manifest.json", json.dumps({"version": VERSION, "sigma_source": "PhishMatrix structured SIEM events",
                         "yara_scope": "ASCII-compatible HTML or MIME text up to 1 MiB. Review matches in context.",
                         "sigma_rules": len(PROFILES), "yara_rules": len(PATTERNS)}, indent=2))
    return stream.getvalue()
