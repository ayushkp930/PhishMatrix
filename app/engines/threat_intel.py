"""Read-only lookups at fixed provider endpoints. No submitted queries are shared."""

import asyncio
import os
from ipaddress import ip_address

import httpx

from app.engines.legacy_intel import additional_lookups
from app.engines.provider_http import failure, provider, request_json

async def virustotal(client: httpx.AsyncClient, domain: str, is_ip: bool) -> dict:
    key = os.getenv("VT_API_KEY", "").strip()
    scope = "ip" if is_ip else "domain"
    if not key:
        return provider("Not configured", scope=scope)
    if os.getenv("PHISHMATRIX_VT_SHARE") != "1":
        return provider("Sharing disabled", scope=scope)
    kind = "ip_addresses" if is_ip else "domains"
    status = 0
    try:
        status, data = await request_json(client, "GET", f"https://www.virustotal.com/api/v3/{kind}/{domain}", headers={"x-apikey": key})
        if status == 404:
            return provider("No record", scope=scope)
        if status == 200:
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = max(0, int(stats.get("malicious", 0)))
            verdict = "Match" if malicious >= 3 else "Weak signal" if malicious else "No match"
            return provider(verdict, scope=scope, malicious=malicious, total_engines=sum(int(value) for value in stats.values()))
    except (httpx.HTTPError, TimeoutError, KeyError, TypeError, ValueError, AttributeError):
        pass
    return provider(failure(status), scope=scope)


async def abuseipdb(client: httpx.AsyncClient, ip: str | None) -> dict:
    key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not ip or not key:
        return provider("No IP" if not ip else "Not configured", scope="ip")
    status = 0
    try:
        status, data = await request_json(
            client, "GET", "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key}, params={"ipAddress": ip, "maxAgeInDays": 30},
        )
        if status == 200 and data["data"]["ipAddress"] == ip:
            score = min(100, max(0, int(data["data"]["abuseConfidenceScore"])))
            return provider("Match" if score >= 50 else "No match", scope="ip", confidence_score=score)
    except (httpx.HTTPError, TimeoutError, KeyError, TypeError, ValueError):
        pass
    return provider(failure(status), scope="ip")


async def threatfox(client: httpx.AsyncClient, indicator: str, scope: str) -> dict:
    key = os.getenv("ABUSECH_AUTH_KEY", "").strip()
    if not key:
        return provider("Not configured", scope=scope)
    status = 0
    try:
        status, data = await request_json(
            client, "POST", "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": key}, json={"query": "search_ioc", "search_term": indicator, "exact_match": True},
        )
        if status == 200 and data.get("query_status") == "no_result":
            return provider("No match", scope=scope)
        if status == 200 and data.get("query_status") == "ok":
            rows = data.get("data")
            if isinstance(rows, list):
                expected = {"domain": {"domain"}, "ip": {"ip:port", "ip"}}[scope]
                exact = any(
                    isinstance(row, dict) and row.get("ioc_type") in expected and
                    str(row.get("ioc", "")).rstrip(".").lower() == indicator
                    for row in rows[:100]
                )
                return provider("Match" if exact else "No match", scope=scope)
    except (httpx.HTTPError, TimeoutError, TypeError, ValueError):
        pass
    return provider(failure(status), scope=scope)


async def urlhaus(client: httpx.AsyncClient, indicator: str, scope: str) -> dict:
    key = os.getenv("ABUSECH_AUTH_KEY", "").strip()
    if not key:
        return provider("Not configured", scope=scope)
    status = 0
    try:
        status, data = await request_json(
            client, "POST", "https://urlhaus-api.abuse.ch/v1/host/",
            headers={"Auth-Key": key}, data={"host": indicator},
        )
        if status == 200 and data.get("query_status") == "no_results":
            return provider("No match", scope=scope)
        if status == 200 and data.get("query_status") == "ok" and data.get("host") == indicator:
            active = any(isinstance(item, dict) and item.get("url_status") == "online" for item in (data.get("urls") or [])[:200])
            return provider("Match" if active else "No active match", scope=scope)
    except (httpx.HTTPError, TimeoutError, KeyError, TypeError, ValueError):
        pass
    return provider(failure(status), scope=scope)


async def urlhaus_url(client: httpx.AsyncClient, url: str) -> dict:
    key = os.getenv("ABUSECH_AUTH_KEY", "").strip()
    if not key:
        return provider("Not configured", scope="url")
    if os.getenv("PHISHMATRIX_URLHAUS_PATH_SHARE") != "1":
        return provider("Sharing disabled", scope="url")
    if "?" in url:
        return provider("Query kept local", scope="url")
    status = 0
    try:
        status, data = await request_json(
            client, "POST", "https://urlhaus-api.abuse.ch/v1/url/",
            headers={"Auth-Key": key}, data={"url": url},
        )
        if status == 200 and data.get("query_status") == "no_results":
            return provider("No match", scope="url")
        if status == 200 and data.get("query_status") == "ok" and data.get("url") == url:
            activity = data.get("url_status")
            if activity in {"online", "offline", "unknown"}:
                return provider("Match" if activity == "online" else "No active match", scope="url")
    except (httpx.HTTPError, TimeoutError, TypeError, ValueError):
        pass
    return provider(failure(status), scope="url")


async def query_all_threat_feeds(client: httpx.AsyncClient, url: str, domain: str, ip: str | None) -> dict:
    try:
        ip_address(domain)
        scope = "ip"
    except ValueError:
        scope = "domain"
    vt, abuse, fox, haus, exact, extra = await asyncio.gather(
        virustotal(client, domain, scope == "ip"),
        abuseipdb(client, ip),
        threatfox(client, domain, scope),
        urlhaus(client, domain, scope),
        urlhaus_url(client, url),
        additional_lookups(client, url, domain, ip, scope),
    )
    return {"virustotal": vt, "abuseipdb": abuse, "threatfox": fox, "urlhaus": haus, "urlhaus_url": exact, **extra}
