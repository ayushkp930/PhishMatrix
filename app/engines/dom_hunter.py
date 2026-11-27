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


def control_enabled(control):
    if control.has_attr("disabled"):
        return False
    for fieldset in control.find_parents("fieldset", disabled=True):
        legend = fieldset.find("legend", recursive=False)
        if legend is None or not any(parent is legend for parent in control.parents):
            return False
    return True


def inspect_html(html: str, context_url: str | None = None) -> tuple[dict, list[Finding]]:
    soup = BeautifulSoup(html, "html.parser")
    for inert in soup.find_all("template"):
        inert.extract()
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
    if context_host:
        for refresh in soup.find_all("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)}, limit=8):
            match = re.fullmatch(r"\s*([0-3])\s*;\s*url\s*=\s*(.+)", refresh.get("content", ""), re.I)
            if match:
                try:
                    target = urlsplit(urljoin(document_base, match[2].strip(" '\"")))
                    if target.hostname and target.scheme in {"http", "https"} and domain_key(target.hostname) != domain_key(context_host):
                        findings.append(finding("HTML_EXTERNAL_REFRESH", "Submitted HTML", "A rapid meta refresh names a different site."))
                        break
                except ValueError:
                    continue
    has_password_form = False
    form_count = 0
    for form in soup.find_all("form", limit=100):
        form_count += 1
        fields = [field for field in form.find_all("input", limit=200)
                  if control_enabled(field) and field.get("form", form.get("id")) == form.get("id")]
        passwords = [field for field in fields if field.get("type", "").lower() == "password"]
        otp_field = any(field.get("name") and "one-time-code" in field.get("autocomplete", "").lower().split() for field in fields)
        if not passwords and not otp_field:
            continue
        has_password_form = has_password_form or bool(passwords)
        method = form.get("method", "").lower()
        try:
            destination = str(form.get("action") or "").strip()
            action = urlsplit(urljoin(document_base, destination) if destination else (context_url or ""))
            host = action.hostname
        except ValueError:
            continue
        if not passwords:
            if (method == "post" and action.scheme in {"http", "https"} and host and context_host
                    and domain_key(host) != domain_key(context_host)):
                findings.append(finding("HTML_OTP_CROSS_ORIGIN", "Submitted HTML", "A form with a one-time code field submits to a different site."))
            continue
        for button in form.find_all(["button", "input"], formaction=True, limit=50):
            default_type = "submit" if button.name == "button" else "text"
            if (not control_enabled(button) or button.get("type", default_type).lower() not in {"submit", "image"}
                    or button.get("form", form.get("id")) != form.get("id")
                    or button.get("formmethod", form.get("method", "get")).lower() == "dialog"):
                continue
            try:
                override = urlsplit(urljoin(document_base, button["formaction"]))
                if (context_host and override.scheme in {"http", "https"} and override.hostname
                        and domain_key(override.hostname) != domain_key(context_host)
                        and (not host or domain_key(override.hostname) != domain_key(host))):
                    findings.append(finding("HTML_SUBMIT_OVERRIDE", "Submitted HTML", "A submit control routes the credential form to another site."))
                    break
            except ValueError:
                continue
        if method == "dialog":
            continue
        if action.scheme == "mailto" and action.path and any(field.get("name") for field in passwords):
            findings.append(finding("HTML_PASSWORD_MAILTO", "Submitted HTML", "A form with a named password field opens an email destination on submission."))
        if not host or action.scheme not in {"http", "https"}:
            continue
        if method == "get" and any(field.get("name") for field in passwords):
            findings.append(finding("HTML_PASSWORD_QUERY", "Submitted HTML", "The explicit GET method can expose a named password field in the URL."))
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
    visible = soup.get_text(" ", strip=True)
    prompt = re.search(r"\b(?:win(?:dows)?\s*\+\s*r|paste\s+(?:the\s+)?command)\b", visible, re.I)
    verification = re.search(r"\b(?:captcha|verify (?:that )?you(?: are|'re) human|human verification|verification step)\b", visible, re.I)
    if prompt:
        context_only = False
        for tag in soup.find_all("script", limit=100):
            if tag.get("src") or tag.get("type", "").lower().split(";")[0].strip() not in {
                "", "module", "text/javascript", "application/javascript", "application/ecmascript", "text/ecmascript"
            }:
                continue
            script = tag.string or ""
            if not re.search(r"navigator\.clipboard\.writeText\s*\(|execCommand\s*\(\s*['\"]copy", script, re.I):
                continue
            if not re.search(r"\b(?:powershell|pwsh|mshta|cmd\.exe)\b", script, re.I):
                continue
            literal = re.search(r"""navigator\.clipboard\.writeText\s*\(\s*['"`]\s*(?:powershell|pwsh|mshta|cmd)(?:\.exe)?\s""", script, re.I)
            if verification and literal:
                findings.append(finding("HTML_CLIPBOARD_EXEC", "Submitted HTML", "Verification language, run/paste instructions and a clipboard call containing a shell command co-occur."))
                break
            context_only = True
        else:
            if context_only:
                findings.append(finding("HTML_CLIPBOARD_CONTEXT", "Submitted HTML", "Clipboard and command cues require independent verification."))
    return {
        "page_title": page_title,
        "forms_inspected": form_count,
        "has_password_form": has_password_form,
        "link_mismatches": matches,
        "network_activity": "None",
    }, findings
