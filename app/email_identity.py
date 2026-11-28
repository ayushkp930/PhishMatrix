"""Header identities and static authentication claims. No DNS or delivery verification."""
import os
import re
from email.utils import parseaddr

from app.engines.dom_hunter import domain_key
from app.engines.heuristics import BRANDS
from app.email_unicode import codepoints, decode_host, inspect_token, scripts

FREE = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "icloud.com", "proton.me"}
ESP = {"amazonses.com", "sendgrid.net", "mailgun.org", "mandrillapp.com", "sparkpostmail.com"}
ROLE = re.compile(r"\b(?:IT support|accounts payable|HR|admin(?:istrator)?|help\s?desk|CEO|CFO|chief (?:executive|financial) officer|payroll|finance department|managing director)\b", re.I)
SERVICE = re.compile(r"(?:^|-)(?:support|billing|security-update|verify)(?:-|$)", re.I)
SUBSCRIBE = re.compile(r"<(?:mailto:[^<>\s@]+@[^<>\s@]+|https://[a-z0-9.-]+(?:/[^<>\s]*)?)>", re.I)


def protected_names():
    internal = {decode_host(v.strip()) for v in os.getenv("PHISHMATRIX_ENTERPRISE_DOMAINS", "").split(",") if v.strip()}
    brands = {name: set(domains) for name, domains in BRANDS.items()}
    for host in internal:
        brands.setdefault(domain_key(host).split(".")[0], set()).add(host)
    for domains in list(brands.values()):
        for host in tuple(domains):
            brands.setdefault(host.split(".")[0], set()).add(host)
    return brands, internal


def is_under(host, roots):
    return any(host == root or host.endswith("." + root) for root in roots)


def inspect_name(ev, value, source, brands, *, host=False):
    decoded = decode_host(value) if host else value
    targets = set(brands)
    if host:
        targets = {k for k, official in brands.items() if not is_under(decoded, official)}
        if "xn--" in value.lower():
            ev.add("EMAIL_IDN", source, value, detail=f"Decoded hostname: {decoded}", decoded=decoded)
    for label in (decoded.split(".")[:-1] if host else re.findall(r"[^\W_]+", decoded)):
        for token in label.split("-"):
            result = inspect_token(token, targets, domain=host)
            if result:
                key, target = result
                ev.add(key, source, value, decoded=decoded, visual_target=target,
                       scripts=sorted(scripts(token)), codepoints=codepoints(token) or [f"U+{ord(c):04X}" for c in token],
                       detail=f"Decoded token {token} resembles {target}.")


def auth_results(msg, from_host, trusted_authserv_id=None):
    claims = {k: [] for k in ("spf", "dkim", "dmarc")}
    failures = []
    aligned = set()
    verified = set()
    # Only a receiver-side caller with a sanitized trust boundary may pass trusted_authserv_id.
    for header in msg.get_all("Authentication-Results", []):
        fields = re.sub(r"\([^()]*\)", "", str(header)).split(";")
        trusted = trusted_authserv_id and fields[0].strip().lower() == trusted_authserv_id.lower()
        for clause in fields[1:]:
            m = re.match(r"\s*(spf|dkim|dmarc)\s*=\s*([a-z]+)\b", clause, re.I)
            if not m:
                continue
            mechanism, status = m[1].lower(), m[2].lower()
            claims[mechanism].append(status)
            if status in {"fail", "softfail"}:
                failures.append((str(header), bool(trusted)))
            prop = {"spf": "smtp.mailfrom", "dkim": "header.d", "dmarc": "header.from"}[mechanism]
            identity = re.search(rf"\b{re.escape(prop)}\s*=\s*<?([^\s;<>]+)", clause, re.I)
            if status == "pass" and from_host and identity and domain_key(decode_host(identity[1].split("@")[-1])) == domain_key(from_host):
                aligned.add(mechanism)
                if trusted:
                    verified.add(mechanism)
    return claims, failures, aligned, verified


def inspect_headers(ev, msg, brands, enterprise, trusted_authserv_id=None):
    fields = {}
    for key in ("From", "Reply-To", "Return-Path"):
        header = str(msg.get(key, ""))
        display, address = parseaddr(header)
        host = address.rpartition("@")[2] if "@" in address else ""
        fields[key] = (display, decode_host(host))
        if host:
            inspect_name(ev, host, key, brands, host=True)
            inspect_name(ev, address.rpartition("@")[0], key, brands)
        if display:
            inspect_name(ev, display, key, brands)
    name, sender = fields["From"]
    claims, failures, aligned, verified = auth_results(msg, sender, trusted_authserv_id)
    trusted_sender = is_under(sender, enterprise) or any(is_under(sender, domains) for domains in brands.values())
    fraud = bool(ev.rows.keys() & {"BEC_BANK_DETAIL_CHANGE", "BEC_EXECUTIVE_PRESSURE", "EMAIL_CREDENTIAL_REPLY", "EMAIL_CREDENTIAL_DEADLINE",
                                    "EMAIL_LINK_MISMATCH", "EMAIL_LINK_IMPERSONATION", "EMAIL_HOMOGRAPH", "HTML_WEBHOOK_FORM"})
    bulk = bool(SUBSCRIBE.search(str(msg.get("List-Unsubscribe", ""))))
    mismatched_brand = any(re.search(rf"\b{re.escape(brand)}\b", name, re.I) and not is_under(sender, domains) for brand, domains in brands.items())
    if sender and (mismatched_brand or (ROLE.search(name) and not trusted_sender)):
        weight = 18 if mismatched_brand or (domain_key(sender) in FREE and fraud) else 12 if fraud else 4 if domain_key(sender) in FREE else 0
        # Weak role signals can be dampened by authenticated enterprise / transactional delivery.
        if not mismatched_brand and verified and (trusted_sender or bulk):
            weight = 0
        ev.add("EMAIL_ROLE_DOMAIN", "From", str(msg["From"]), weight=weight)
    label = domain_key(sender).split(".")[0]
    if "-" in label and SERVICE.search(label) and not trusted_sender:
        ev.add("EMAIL_CORPORATE_LURE", "From", sender, weight=12 if fraud else 0)
    risky_identity = ("EMAIL_HOMOGRAPH" in ev.rows or "EMAIL_TYPO_DOMAIN" in ev.rows
                      or "EMAIL_CORPORATE_LURE" in ev.rows or mismatched_brand
                      or ("EMAIL_ROLE_DOMAIN" in ev.rows and (domain_key(sender) in FREE or bool(enterprise))))
    if risky_identity and {"BEC_BANK_DETAIL_CHANGE", "BEC_EXECUTIVE_PRESSURE"} <= ev.rows.keys():
        ev.add("BEC_PAYMENT_DIVERSION", "Correlated email evidence", ev.rows["BEC_BANK_DETAIL_CHANGE"]["matched_evidence"],
               detail="Changed payment destination and pressure accompany a questionable sender or linked identity.")
    for key, rule in (("Reply-To", "EMAIL_REPLY_TO"), ("Return-Path", "EMAIL_ENVELOPE")):
        other = fields[key][1]
        if not sender or not other or domain_key(sender) == domain_key(other):
            continue
        if domain_key(other) in ESP and ("dkim" in verified or ("dkim" in aligned and not fraud)):
            continue
        ev.add(rule, key, str(msg[key]), detail=f"{sender} and {other} use different mail domains.")
        if fraud:
            if key == "Reply-To" and ev.rows.keys() & {"EMAIL_ARCHIVED_THREAT", "EMAIL_LINK_MISMATCH", "EMAIL_LINK_IMPERSONATION"}:
                ev.add("EMAIL_REPLY_TO_CORROBORATED", key, str(msg[key]))
            else:
                ev.add("EMAIL_ROUTE_RISK", key, str(msg[key]))
    for header, trusted in failures:
        ev.add("EMAIL_AUTH_CLAIM", "Authentication-Results", header)
        if trusted or fraud:
            ev.add("EMAIL_AUTH_CORRELATED", "Authentication-Results", header, weight=10 if trusted else 5)
    return claims, sorted(aligned), sorted(verified)
