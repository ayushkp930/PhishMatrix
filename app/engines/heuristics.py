"""Local lexical signals for likely brand impersonation."""

import re
from ipaddress import ip_address
from urllib.parse import parse_qsl, unquote, urlsplit

import idna

from app.engines.forensics import registrable_domain
from app.scoring import Finding, finding

BRANDS = {
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "live.com"},
    "google": {"google.com", "google.co.in"},
    "paypal": {"paypal.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "netflix": {"netflix.com"},
    "github": {"github.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "sbicard.com"},
    "hdfc": {"hdfcbank.com", "hdfc.com"},
    "icici": {"icicibank.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "indiapost": {"indiapost.gov.in"},
    "parivahan": {"parivahan.gov.in"},
}
ABUSED_SUFFIXES = {"top", "xyz", "buzz", "icu", "click", "link", "zip"}
HOSTING = {"github.io", "pages.dev", "workers.dev", "vercel.app", "netlify.app", "web.app"}
LURES = r"\b(?:login|sign[ -]?in|verify|kyc|account|unlock|update|reward|payment|e[ -]?challan)\b"
CONFUSABLES = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i", "ѕ": "s", "ӏ": "l", "ο": "o", "0": "o"})
REDIRECT_KEYS = {"redirect", "redirect_uri", "return", "returnurl", "next", "continue", "return_to"}


def offsite_redirect(path: str, query: str, root: str) -> bool:
    if not query or not re.search(LURES, re.sub(r"[_/.-]", " ", unquote(path).lower())):
        return False
    try:
        fields = parse_qsl(query, max_num_fields=40)
    except ValueError:
        return False
    for key, value in fields:
        if key.lower() not in REDIRECT_KEYS:
            continue
        try:
            target = urlsplit(value)
            host = target.hostname
            if (target.scheme in {"http", "https"} or not target.scheme) and host:
                if (registrable_domain(host) or host) != root:
                    return True
        except ValueError:
            continue
    return False


def one_edit_away(a: str, b: str) -> bool:
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        differences = [i for i, (left, right) in enumerate(zip(a, b)) if left != right]
        return len(differences) == 1 or (
            len(differences) == 2 and differences[1] == differences[0] + 1
            and a[differences[0]] == b[differences[1]] and a[differences[1]] == b[differences[0]]
        )
    short, long = sorted((a, b), key=len)
    first = next((i for i, (left, right) in enumerate(zip(short, long)) if left != right), len(short))
    return short[first:] == long[first + 1:]


def lexical_findings(host: str, path: str, query: str) -> list[Finding]:
    if re.search(r"\b(?:login|signin|sign-in|verify|kyc)\b", unquote(path), re.I):
        try:
            ip_address(host)
        except ValueError:
            pass
        else:
            return [finding("URL_IP_LOGIN", "URL heuristic", "The sign-in route uses a numeric address in place of a domain.")]
    root = registrable_domain(host)
    if not root:
        return []
    label = root.split(".", 1)[0]
    try:
        unicode_label = idna.decode(label)
    except idna.IDNAError:
        unicode_label = label
    comparable = unicode_label.translate(CONFUSABLES)
    skeletons = {comparable, comparable.replace("1", "l"), comparable.replace("1", "i")}
    lure_text = re.sub(r"[_/?.&=-]", " ", f"{host} {unquote(path)} {unquote(query)}".lower())
    findings = []
    if label.startswith("xn--"):
        findings.append(finding("PUNYCODE_LABEL", "URL heuristic", "The registered label uses IDNA encoding."))
    shared_tenant = any(host.endswith("." + suffix) for suffix in HOSTING)
    if shared_tenant:
        findings.append(finding("HOSTED_TENANT", "URL heuristic", "Registration age is for the hosting platform, not the tenant."))
    if offsite_redirect(path, query, root):
        findings.append(finding("URL_OFFSITE_REDIRECT", "URL heuristic", "A login or payment path carries a redirect parameter naming a different site. Destination omitted."))
    if root.rsplit(".", 1)[-1] in ABUSED_SUFFIXES:
        findings.append(finding("RISKY_SUFFIX", "URL heuristic", "Suffix contributes a small context signal."))
    subdomains = host[:-len(root)].strip(".").split(".") if host.endswith("." + root) else []
    for brand, official in BRANDS.items():
        if root in official:
            continue
        if brand in subdomains and re.search(LURES, lure_text):
            findings.append(finding("URL_BRAND_SUBDOMAIN", "URL heuristic", f"{brand} appears before the actual registered domain, {root}."))
            break
        if len(brand) >= 5 and brand in skeletons and unicode_label != brand:
            findings.append(finding("BRAND_CONFUSABLE", "URL heuristic", f"The registered label uses characters that resemble {brand}."))
            break
        if len(brand) >= 5 and one_edit_away(label, brand):
            findings.append(finding("BRAND_LOOKALIKE", "URL heuristic", f"The registered label resembles {brand}."))
            break
        if re.search(rf"\b{brand}\b", host.replace("_", "-")) and re.search(LURES, lure_text):
            tenant_cue = shared_tenant and re.search(LURES, re.sub(r"[_.-]", " ", host))
            rule = "URL_SHARED_TENANT_LURE" if tenant_cue else "BRAND_LURE"
            findings.append(finding(rule, "URL heuristic", f"{brand} appears alongside a credential or payment lure."))
            break
    return findings
