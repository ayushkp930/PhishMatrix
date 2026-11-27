"""Legacy provider keys and privacy-preserving, read-only enrichment."""

import asyncio
import os
import re
from functools import lru_cache
from pathlib import Path
from ipaddress import IPv4Address
from urllib.parse import urlsplit, urlunsplit

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from app.engines.provider_http import bounded_lookup, failure, provider, request_json

LOOKUP_ERRORS = (httpx.HTTPError, TimeoutError, TypeError, KeyError, ValueError, AttributeError, RecursionError)
HASH = re.compile(r"(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})")
KEYS = {
    "webrisk": "WEBRISK_API_KEY", "urlscan": "URLSCAN_API_KEY", "otx": "OTX_API_KEY",
    "pulsedive": "PULSEDIVE_API_KEY", "greynoise": "GREYNOISE_API_KEY", "shodan": "SHODAN_API_KEY",
    "malshare": "MALSHARE_API_KEY", "mailboxlayer": "MAILBOXLAYER_API_KEY",
    "httpbl": "HTTPBL_API_KEY", "ip_api": "IP_API_KEY",
}
NAMES = {
    "webrisk": "Google Web Risk", "urlscan": "URLScan", "otx": "AlienVault OTX",
    "pulsedive": "Pulsedive", "greynoise": "GreyNoise", "shodan": "Shodan",
    "malshare": "MalShare", "mailboxlayer": "Mailboxlayer", "httpbl": "Project Honey Pot",
    "ip_api": "IP-API Pro", "internetdb": "Shodan InternetDB", "crtsh": "Certificate Transparency",
    "maltrail": "Maltrail", "hudsonrock": "Hudson Rock",
}


def secret(name: str) -> str:
    return os.getenv(KEYS[name], "").strip()


async def lookup(client, endpoint, scope, parse, *, missing=(404,), **kwargs):
    try:
        status, data = await request_json(client, "GET", endpoint, **kwargs)
        if status in missing:
            return provider("No record", scope=scope)
        if status == 200:
            result, metadata = parse(data)
            return provider(result, scope=scope, **metadata)
        return provider(failure(status), scope=scope)
    except LOOKUP_ERRORS:
        return provider("Unavailable", scope=scope)


def parse_webrisk(data):
    if data == {}:
        return "No match", {}
    threat_types = data["threat"]["threatTypes"]
    known = {"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"}
    if not isinstance(threat_types, list) or not threat_types or not set(threat_types) <= known:
        raise ValueError()
    return "Match", {"threat_types": threat_types}


def parse_urlscan(data):
    results = data["results"]
    if not isinstance(results, list):
        raise ValueError()
    return ("Observed" if results else "No record"), {"returned_results": len(results)}


def parse_otx(data):
    count = data["pulse_info"]["count"]
    if type(count) is not int or count < 0:
        raise ValueError()
    return ("Observed" if count else "No match"), {"pulses": count}


def parse_pulsedive(data):
    risk = data["risk"].lower()
    if risk not in {"none", "unknown", "low", "medium", "high", "critical"}:
        raise ValueError()
    return ("Match" if risk in {"high", "critical"} else "Observed"), {"risk": risk}


def parse_greynoise(data):
    classification = data["classification"].lower()
    if classification not in {"malicious", "benign", "unknown"}:
        raise ValueError()
    return ("Match" if classification == "malicious" else "Observed"), {"classification": classification}


def parse_shodan(data):
    if not isinstance(data["ports"], list):
        raise ValueError()
    return "Observed", {}


def parse_mailboxlayer(data):
    mx = data["mx_found"]
    if type(mx) is not bool:
        raise ValueError()
    return ("Observed" if mx else "No MX record"), {"mx_found": mx}


def parse_ip_api(data):
    if data.get("status") != "success":
        raise ValueError()
    return "Observed", {"hosting": data.get("hosting") is True, "proxy": data.get("proxy") is True}


def parse_malshare(data, digest):
    candidates = [data.get(name, "") for name in ("md5", "sha1", "sha256", "MD5", "SHA1", "SHA256")]
    if digest in {value.lower() for value in candidates if isinstance(value, str)}:
        return "Match", {}
    raise ValueError()


async def malshare_lookup(client: httpx.AsyncClient, digest: str) -> dict:
    key = secret("malshare")
    if not HASH.fullmatch(digest):
        return provider("Invalid hash", scope="hash")
    if not key:
        return provider("Not configured", scope="hash")
    return await lookup(
        client, "https://malshare.com/api.php", "hash", lambda data: parse_malshare(data, digest),
        params={"api_key": key, "action": "details", "hash": digest},
    )


async def httpbl_lookup(ip: str) -> dict:
    key = secret("httpbl")
    if not re.fullmatch(r"[a-z]{12}", key):
        return provider("Invalid configuration", scope="ip")
    try:
        octets = str(IPv4Address(ip)).split(".")
    except ValueError:
        return provider("IPv4 required", scope="ip")
    # The service requires its key as a DNS label. Only the deployment's configured resolver sees the query.
    question = ".".join([key, *reversed(octets), "dnsbl", "httpbl", "org", ""])
    try:
        reply = await dns.asyncresolver.resolve(question, "A", search=False, lifetime=2.5)
        for record in reply:
            parts = [int(part) for part in record.address.split(".")]
            if parts[0] == 127 and parts[3] in range(8):
                return provider("Match" if parts[3] and parts[2] else "Observed", scope="ip",
                                days_since_activity=parts[1], threat_score=parts[2])
        return provider("Unavailable", scope="ip")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return provider("No match", scope="ip")
    except (dns.exception.DNSException, OSError, ValueError):
        return provider("Unavailable", scope="ip")


def parse_hudsonrock(data):
    # Keep only the aggregate. Never return affected identities, credentials, or provider records.
    total = data.get("total")
    if type(total) is not int or total < 0:
        raise ValueError()
    return ("Observed" if total else "No record"), {"aggregate_records": total}


def parse_certificates(data):
    if any(not isinstance(row, dict) or type(row.get("id")) is not int for row in data):
        raise ValueError()
    return ("Observed" if data else "No record"), {"certificate_count": len({row["id"] for row in data})}


@lru_cache(maxsize=2)
def read_maltrail(path: Path, modified: int, size: int):
    if size > 8 * 1024 * 1024:
        raise ValueError("Maltrail snapshot too large")
    with path.open("rb") as stream:
        data = stream.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024:
        raise ValueError("Maltrail snapshot too large")
    return frozenset(line.strip().lower().rstrip(".") for line in data.decode().splitlines()
                     if line and not line.startswith("#") and len(line) <= 253)


async def maltrail_lookup(filename, host):
    path = Path(filename)
    try:
        metadata = path.stat()
        domains = await asyncio.to_thread(read_maltrail, path, metadata.st_mtime_ns, metadata.st_size)
        if not domains:
            return provider("Unavailable", scope="domain")
        return provider("Observed" if host in domains else "No record", scope="domain", listed=host in domains)
    except (ValueError, OSError):
        return provider("Unavailable", scope="domain")


async def additional_lookups(client, url, host, ip, scope):
    results = {
        name: provider("Not configured", scope="ip" if name in {"greynoise", "shodan", "httpbl", "ip_api"} else scope)
        for name in KEYS
    }
    results["malshare"] = provider("Hash lookup available" if secret("malshare") else "Not configured", scope="hash")
    jobs = {}
    if scope == "domain":
        if os.getenv("PHISHMATRIX_PUBLIC_INTEL") == "1":
            jobs["crtsh"] = lookup(client, "https://crt.sh/", scope, parse_certificates,
                                  expected=list, params={"q": host, "output": "json"})
            jobs["hudsonrock"] = lookup(
                client, "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain",
                scope, parse_hudsonrock, params={"domain": host},
            )
        if filename := os.getenv("PHISHMATRIX_MALTRAIL_FILE", "").strip():
            jobs["maltrail"] = maltrail_lookup(filename, host)

    if key := secret("webrisk"):
        parts = urlsplit(url)
        full_public_path = os.getenv("PHISHMATRIX_WEBRISK_PATH_SHARE") == "1"
        checked = urlunsplit((parts.scheme, parts.netloc, parts.path if full_public_path else "/", "", ""))
        lookup_scope = "url" if checked == url else scope
        jobs["webrisk"] = lookup(
            client, "https://webrisk.googleapis.com/v1/uris:search", lookup_scope, parse_webrisk,
            missing=(), headers={"x-goog-api-key": key},
            params=[("uri", checked), ("threatTypes", "SOCIAL_ENGINEERING"), ("threatTypes", "MALWARE"), ("threatTypes", "UNWANTED_SOFTWARE")],
        )
    if key := secret("urlscan"):
        if scope == "domain":
            jobs["urlscan"] = lookup(client, "https://urlscan.io/api/v1/search/", scope, parse_urlscan,
                                     headers={"api-key": key}, params={"q": f'page.domain:"{host}"', "size": 5})
        else:
            jobs["urlscan"] = lookup(client, "https://urlscan.io/api/v1/search/", scope, parse_urlscan,
                                     headers={"api-key": key}, params={"q": f'page.ip:"{host}"', "size": 5})
    if key := secret("otx"):
        if scope == "domain":
            jobs["otx"] = lookup(client, f"https://otx.alienvault.com/api/v1/indicators/domain/{host}/general", scope,
                                 parse_otx, headers={"X-OTX-API-KEY": key})
        else:
            version = "IPv6" if ":" in host else "IPv4"
            jobs["otx"] = lookup(client, f"https://otx.alienvault.com/api/v1/indicators/{version}/{host}/general", scope,
                                 parse_otx, headers={"X-OTX-API-KEY": key})
    if key := secret("pulsedive"):
        jobs["pulsedive"] = lookup(client, "https://pulsedive.com/api/info.php", scope, parse_pulsedive,
                                   params={"indicator": host, "key": key})
    if key := secret("mailboxlayer"):
        if scope == "domain":
            jobs["mailboxlayer"] = lookup(
                client, "https://api.apilayer.net/mailboxlayer/api/check", "domain", parse_mailboxlayer,
                missing=(), params={"access_key": key, "email": f"postmaster@{host}", "smtp": 0},
            )
        else:
            results["mailboxlayer"] = provider("Domain required", scope="domain")

    for name in ("greynoise", "shodan", "httpbl", "ip_api"):
        if secret(name) and not ip:
            results[name] = provider("No IP", scope="ip")
    if ip:
        if key := secret("greynoise"):
            jobs["greynoise"] = lookup(client, f"https://api.greynoise.io/v3/community/{ip}", "ip",
                                       parse_greynoise, headers={"key": key})
        if key := secret("shodan"):
            jobs["shodan"] = lookup(client, f"https://api.shodan.io/shodan/host/{ip}", "ip",
                                    parse_shodan, params={"key": key, "minify": "true"})
        elif os.getenv("PHISHMATRIX_PUBLIC_INTEL") == "1":
            jobs["internetdb"] = lookup(client, f"https://internetdb.shodan.io/{ip}", "ip", parse_shodan)
        if secret("httpbl"):
            jobs["httpbl"] = httpbl_lookup(ip)
        if key := secret("ip_api"):
            jobs["ip_api"] = lookup(client, f"https://pro.ip-api.com/json/{ip}", "ip", parse_ip_api,
                                    params={"key": key, "fields": "status,proxy,hosting"})
    isolated = [bounded_lookup(job, provider("Unavailable", scope=results.get(name, {}).get("scope", scope)))
                for name, job in jobs.items()]
    results.update(zip(jobs, await asyncio.gather(*isolated), strict=True))
    return results
