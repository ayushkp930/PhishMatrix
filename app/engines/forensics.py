import asyncio
import socket
import time
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

import httpx
import tldextract
from urllib.parse import urlsplit

from app.engines.provider_http import request_json
from app.security import printable

PUBLIC_SUFFIXES = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())
WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "in": "whois.nixiregistry.in",
}
NEW_DOMAIN_MAX_DAYS = 30
RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
BUILTIN_RDAP = {
    "com": "https://rdap.verisign.com/com/v1/",
    "net": "https://rdap.verisign.com/net/v1/",
    "in": "https://rdap.nixiregistry.in/rdap/",
}
bootstrap_cache = {"retry_at": 0.0, "services": {}}


def trusted_registry_base(base: str) -> bool:
    if not isinstance(base, str) or not base.startswith("https://"):
        return False
    try:
        parts = urlsplit(base)
        host = parts.hostname
        return bool(host and "." in host and parts.netloc == host and not parts.query and not parts.fragment
                    and not host.endswith((".local", ".internal", ".localhost")) and not host.replace(".", "").isdigit())
    except ValueError:
        return False


async def registry_base(client: httpx.AsyncClient, tld: str) -> str | None:
    if tld in BUILTIN_RDAP:
        return BUILTIN_RDAP[tld]
    now = time.monotonic()
    if now >= bootstrap_cache["retry_at"]:
        bootstrap_cache["retry_at"] = now + 60
        try:
            status, data = await request_json(client, "GET", RDAP_BOOTSTRAP)
            if status == 200:
                services = {}
                for suffixes, urls in data["services"]:
                    base = next((url for url in urls if trusted_registry_base(url)), None)
                    if base:
                        services.update(dict.fromkeys(suffixes, base))
                if services:
                    bootstrap_cache.update(services=services, retry_at=now + 86400)
        except (httpx.HTTPError, TimeoutError, TypeError, ValueError, KeyError):
            pass
    return bootstrap_cache["services"].get(tld)



def raw_socket_whois(domain: str) -> dict:
    server = WHOIS_SERVERS.get(domain.rsplit(".", 1)[-1])
    if not server:
        return {}
    deadline = time.monotonic() + 2.0
    try:
        with socket.create_connection((server, 43), timeout=2.0) as sock:
            sock.sendall(f"{domain}\r\n".encode("ascii"))
            response = bytearray()
            while len(response) < 65536:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return {}
                sock.settimeout(remaining)
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
    except OSError:
        return {}

    fields = {}
    for line in response.decode("utf-8", errors="replace").splitlines():
        name, separator, value = line.partition(":")
        if separator and value.strip():
            fields.setdefault(name.strip().lower(), value.strip())
    return {
        "registrar": fields.get("registrar"),
        "creation_date": fields.get("creation date") or fields.get("created on"),
        "expiry_date": fields.get("registry expiry date") or fields.get("expiration date"),
        "abuse_contact": fields.get("registrar abuse contact email"),
    }


def parse_registration_time(value: str, now: datetime) -> tuple[datetime, bool] | None:
    if not isinstance(value, str):
        return None
    try:
        registered = datetime.fromisoformat(value)
    except ValueError:
        return None
    date_only = len(value) == 10
    if date_only:
        registered = registered.replace(tzinfo=timezone.utc)
    elif registered.tzinfo is None:
        return None
    else:
        try:
            registered = registered.astimezone(timezone.utc)
        except OverflowError:
            return None
    if registered > now:
        return None
    return registered, date_only


def registrable_domain(hostname: str) -> str:
    return PUBLIC_SUFFIXES(hostname).top_domain_under_public_suffix


async def lookup_whois_rdap(client: httpx.AsyncClient, domain: str) -> dict:
    root = registrable_domain(domain)
    try:
        ip_address(domain)
        status = "not_applicable"
    except ValueError:
        status = "unavailable"
    registration = {
        "queried_domain": root or domain,
        "registrar": "Unknown",
        "creation_date": "Not applicable" if status == "not_applicable" else "Unknown",
        "expiry_date": "Unknown",
        "registration_timestamp": None,
        "registration_source": None,
        "registration_status": status,
        "domain_age_days": None,
        "is_registered_within_24h": None,
        "is_newly_registered": None,
        "abuse_contact": None,
        "nameservers": [],
    }
    if not root:
        return registration

    now = datetime.now(timezone.utc)
    created = None
    source = "RDAP"
    try:
        base = await registry_base(client, root.rsplit(".", 1)[-1])
        if base:
            status, data = await request_json(client, "GET", base.rstrip("/") + "/domain/" + root)
            if status == 200 and data.get("ldhName", "").lower().rstrip(".") == root:
                dates = (
                    parse_registration_time(event.get("eventDate"), now)
                    for event in data.get("events", [])
                    if isinstance(event, dict) and event.get("eventAction") == "registration"
                )
                created = max((date for date in dates if date is not None), default=None)
                registration["expiry_date"] = next(
                    (event["eventDate"][:10] for event in data.get("events", [])
                     if isinstance(event, dict) and event.get("eventAction") == "expiration"
                     and isinstance(event.get("eventDate"), str)),
                    "Unknown",
                )
                registration["nameservers"] = [
                    printable(entry["ldhName"], 253).lower()
                    for entry in data.get("nameservers", [])
                    if isinstance(entry, dict) and isinstance(entry.get("ldhName"), str)
                ][:4]
                for entity in data.get("entities", []):
                    if not isinstance(entity, dict) or "registrar" not in (entity.get("roles") or []):
                        continue
                    vcard = entity.get("vcardArray")
                    if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
                        name = next((row[3] for row in vcard[1] if isinstance(row, list) and len(row) > 3
                                     and row[0] in ("fn", "org") and isinstance(row[3], str)), None)
                        if name:
                            registration["registrar"] = printable(name, 120)
                            break
    except (httpx.HTTPError, TimeoutError, ValueError, AttributeError, TypeError):
        pass

    if not created and root.rsplit(".", 1)[-1] in WHOIS_SERVERS:
        source = "WHOIS"
        try:
            raw = await asyncio.wait_for(asyncio.to_thread(raw_socket_whois, root), timeout=2.5)
        except TimeoutError:
            raw = {}
        created = parse_registration_time(raw.get("creation_date"), now)
        registration["registrar"] = printable(raw.get("registrar") or "Unknown", 120)
        registration["expiry_date"] = (raw.get("expiry_date") or registration["expiry_date"])[:10]
        registration["abuse_contact"] = printable(raw["abuse_contact"], 254) if raw.get("abuse_contact") else None

    if created:
        registered, date_only = created
        age = now - registered
        # A date without a time confirms same-day registration only on that UTC date.
        within_24h = registered.date() == now.date() if date_only else age < timedelta(days=1)
        registration.update(
            creation_date=registered.date().isoformat(),
            registration_timestamp=None if date_only else registered.isoformat(),
            registration_source=source,
            registration_status="confirmed",
            domain_age_days=age.days,
            is_registered_within_24h=within_24h,
            is_newly_registered=age.days <= NEW_DOMAIN_MAX_DAYS,
        )
    return registration
