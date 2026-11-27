"""Inert HTML interpretation. No script execution or network access."""

import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

import tldextract
from app.scoring import Finding, finding
from app.security import printable


# Keep different tenants of shared hosting services separate in artifact comparisons.
TENANT_SUFFIXES = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=(), include_psl_private_domains=True)


def domain_key(host: str) -> str:
    normalized = host.lower().rstrip(".")
    return TENANT_SUFFIXES(normalized).top_domain_under_public_suffix or normalized


def link_mismatches(soup: BeautifulSoup) -> int:
    count = 0
    for anchor in soup.find_all("a", href=True, limit=200):
        text = anchor.get_text(" ", strip=True)
        if len(text) > 300 or not re.match(r"^https?://\S+$", text, flags=re.I):
            continue
        try:
            shown = urlsplit(text).hostname
            actual = urlsplit(anchor["href"]).hostname
        except ValueError:
            continue
        if shown and actual and domain_key(shown) != domain_key(actual):
            count += 1
    return count


def inspect_html(html: str, context_url: str | None = None) -> tuple[dict, list[Finding]]:
    soup = BeautifulSoup(html, "html.parser")
    page_title = printable(soup.title.get_text(" ", strip=True), 120) if soup.title else None
    findings = []
    matches = link_mismatches(soup)
    if matches:
        findings.append(finding("HTML_LINK_MISMATCH", "Submitted HTML", f"{matches} URL label(s) point to a different domain."))
    context_host = urlsplit(context_url).hostname if context_url else None
    document_base = context_url or ""
    base_tag = soup.find("base", href=True)
    if base_tag:
        try:
            base = urlsplit(urljoin(document_base, base_tag["href"]))
            if base.scheme in {"http", "https"} and base.hostname:
                document_base = base.geturl()
        except ValueError:
            pass
    has_password_form = False
    form_count = 0
    for form in soup.find_all("form", limit=100):
        form_count += 1
        password = form.find("input", attrs={"type": re.compile("^password$", re.I)})
        if not password:
            continue
        has_password_form = True
        try:
            destination = str(form.get("action") or "").strip()
            action = urlsplit(urljoin(document_base, destination) if destination else (context_url or ""))
            host = action.hostname
        except ValueError:
            continue
        if not host:
            continue
        target = domain_key(host)
        if (host == "api.telegram.org" and action.path.startswith("/bot")) or (
            host in {"discord.com", "discordapp.com"} and action.path.startswith("/api/webhooks/")
        ):
            findings.append(finding("HTML_WEBHOOK_FORM", "Submitted HTML", f"A password form references {target}. Endpoint data omitted."))
        elif context_host and target != domain_key(context_host):
            uses_foreign_base = bool(destination and not urlsplit(destination).netloc and base_tag)
            rule = "HTML_CREDENTIAL_FORM_REDIRECT" if uses_foreign_base else "HTML_CROSS_ORIGIN_FORM"
            findings.append(finding(rule, "Submitted HTML", f"A password form submits to {target}."))
        if action.scheme == "http":
            findings.append(finding("HTML_INSECURE_PASSWORD", "Submitted HTML", "The form destination uses unencrypted HTTP."))
    prompt = re.search(r"\b(?:win(?:dows)?\s*\+\s*r|paste\s+(?:the\s+)?command)\b", soup.get_text(" ", strip=True), re.I)
    clipboard_script = False
    for tag in soup.find_all("script", limit=100):
        source = (tag.string or "").lower()
        if re.search(r"""navigator\.clipboard\.writetext|execcommand\s*\(\s*['"]copy""", source) and re.search(r"\b(?:powershell|mshta|cmd\.exe)\b", source):
            clipboard_script = True
            break
    if clipboard_script and prompt:
        findings.append(finding("HTML_CLIPBOARD_EXEC", "Submitted HTML", "Clipboard write, a command shell cue and a run/paste instruction co-occur."))
    return {
        "page_title": page_title,
        "forms_inspected": form_count,
        "has_password_form": has_password_form,
        "link_mismatches": matches,
        "network_activity": "None",
    }, findings
