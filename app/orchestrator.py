"""Coordinate passive lookups, local analysis, and SOC-ready output."""

import asyncio
import os
import time
from datetime import datetime, timezone
from uuid import uuid4

import httpx

from app.dataset_model import dataset_context
from app.engines.analyst import summarize
from app.engines.legacy_intel import NAMES as LEGACY_PROVIDER_NAMES
from app.engines.dom_hunter import inspect_html
from app.engines.forensics import lookup_whois_rdap
from app.engines.heuristics import lexical_findings
from app.engines.soc_generator import generate_blue_team_arsenal, siem_event
from app.engines.threat_intel import query_all_threat_feeds
from app.historical_intel import SOURCE as HISTORICAL_SOURCE, historical_url_lookup
from app.intel import lookup_snapshot
from app.scoring import VERSION, assess, finding
from app.security import defang_ioc, normalize_target
from app.whitelist import is_whitelisted_domain

PROVIDER_NAMES = {"virustotal": "VirusTotal", "abuseipdb": "AbuseIPDB", "threatfox": "ThreatFox", "urlhaus": "URLhaus · host", "urlhaus_url": "URLhaus · URL", **LEGACY_PROVIDER_NAMES}
IP_REPUTATION_SOURCES = {"virustotal", "abuseipdb"}


def recommendations(verdict: str) -> list[dict]:
    guidance = {
        "MALICIOUS": [
            ("P1", "Corroborate and contain", "Verify the exact URL or artifact before blocking it. Hunt for user access in proxy and DNS logs."),
            ("P2", "Assess user exposure", "Check for credential submission or command execution before resetting accounts or isolating endpoints."),
        ],
        "SUSPICIOUS": [
            ("P2", "Open an analyst review", "Check the sender and destination in trusted sources. Review page contents using approved isolation if needed."),
            ("P3", "Hunt for the indicator", "Validate the generated SIEM rule against your schema and run it in audit mode."),
        ],
        "INCONCLUSIVE": [("P3", "Collect missing evidence", "Check provider availability and add trusted email, HTML or gateway evidence.")],
        "CLEAN": [("INFO", "Continue monitoring", "The completed reputation check found no listing. Confirm the delivery context before trusting the indicator.")],
    }
    return [{"priority": priority, "category": category, "action": action} for priority, category, action in guidance[verdict]]


def registration_label(whois: dict) -> str:
    days = whois["domain_age_days"]
    if days is None:
        return whois["creation_date"]
    if whois["is_registered_within_24h"]:
        age = "Under 24 hours" if whois["registration_timestamp"] else "Registered today (UTC)"
    else:
        age = f"{days} days"
    return f"{age} ({whois['creation_date']} · {whois['registration_source']})"


def safe_target(target: dict) -> dict:
    host, ip = target["domain"], target["resolved_ip"]
    url = target["url"].split("?", 1)[0]
    defanged = defang_ioc(url, host, ip)
    return {
        "domain": host,
        "resolved_ip": ip,
        "url": defanged["defanged_url"],
        "query_redacted": bool(target["query"]),
        **defanged,
    }


def reputation_coverage(target: dict, feeds: dict, allowlisted: bool) -> dict:
    # For a web URL, a negative IP/host lookup or a limited blocklist cannot cover a specific page.
    address_only = target["domain"] == target["resolved_ip"] and target["path"] == "/" and not target["query"]
    if address_only:
        scope = "ip"
        sources = [PROVIDER_NAMES[name] for name in sorted(IP_REPUTATION_SOURCES & feeds.keys())
                   if feeds[name]["scope"] == "ip" and feeds[name]["status"] == "No match"]
    else:
        scope = "url"
        web_risk = feeds.get("webrisk", {})
        sources = [PROVIDER_NAMES["webrisk"]] if (
            web_risk.get("scope") == "url" and web_risk.get("status") == "No match"
        ) else []
    if sources:
        note = f"No match from {', '.join(sources)} for this {scope.upper()}."
    elif allowlisted:
        note = "Allowlisted root. External reputation checks were skipped."
    else:
        note = f"No completed {scope.upper()}-level negative reputation check. Host and historical results cannot establish current safety."
    return {"scope": scope, "negative_sources": sources, "sufficient_for_no_match": bool(sources), "detail": note}


async def investigate_target(raw_input: str) -> dict:
    started = time.monotonic()
    resolve = os.getenv("PHISHMATRIX_DNS_LOOKUPS") == "1"
    if resolve:
        target = await asyncio.wait_for(asyncio.to_thread(normalize_target, raw_input), 3.0)
    else:
        target = normalize_target(raw_input, resolve=False)
    url, domain, ip = target["url"], target["domain"], target["resolved_ip"]
    findings = lexical_findings(domain, target["path"], target["query"])
    model = dataset_context(target)
    snapshot, historical = await asyncio.gather(
        asyncio.to_thread(lookup_snapshot, url, domain, ip),
        asyncio.to_thread(historical_url_lookup, url),
    )
    if historical["labels"]:
        labels = ", ".join(historical["labels"])
        findings.append(finding(
            "TI_HISTORICAL_URL", HISTORICAL_SOURCE,
            f"Archived URL label(s): {labels}. Current activity is unverified.",
        ))
    for hit in snapshot["hits"]:
        identifier = {"url": "TI_URL_EXACT", "domain": "TI_DOMAIN", "ip": "TI_IP"}[hit["scope"]]
        findings.append(finding(identifier, hit["source"], f"Exact {hit['scope']} match. Valid until {hit['expires_at']}."))
    is_allowlist_candidate = not findings and is_whitelisted_domain(domain, url)

    async with httpx.AsyncClient(timeout=3.0, follow_redirects=False) as client:
        if is_allowlist_candidate:
            whois = await lookup_whois_rdap(client, domain)
            allowlisted = whois["registration_status"] == "confirmed" and whois["is_newly_registered"] is False
            if allowlisted and os.getenv("PHISHMATRIX_INCLUDE_ALLOWLIST") != "1":
                feeds = {}
            else:
                allowlisted = False
                feeds = await query_all_threat_feeds(client, url, domain, ip)
        else:
            allowlisted = False
            whois, feeds = await asyncio.gather(
                lookup_whois_rdap(client, domain),
                query_all_threat_feeds(client, url, domain, ip),
            )

    if whois["is_newly_registered"]:
        identifier = "NRD_24H" if whois["is_registered_within_24h"] else "NRD_30D"
        findings.append(finding(identifier, whois["registration_source"], f"{whois['queried_domain']} · {registration_label(whois)}"))
    for name, result in feeds.items():
        if result["status"] != "Match":
            continue
        scope = result["scope"]
        identifier = {"ip": "TI_IP", "domain": "TI_DOMAIN", "url": "TI_URL_EXACT"}.get(scope)
        if identifier:
            findings.append(finding(identifier, PROVIDER_NAMES[name], f"Observed {scope}-level reputation evidence."))

    coverage = reputation_coverage(target, feeds, allowlisted)
    result = assess(findings, coverage_sufficient=coverage["sufficient_for_no_match"])
    verdict = result["verdict"]
    async with httpx.AsyncClient(timeout=1.8, follow_redirects=False) as client:
        analyst = await summarize(client, result)
    case_id = str(uuid4())
    providers = {PROVIDER_NAMES[name]: feed for name, feed in feeds.items()}
    providers.update({f"AI · {name}": {"status": state} for name, state in analyst["providers"].items()})
    providers["Kaggle historical index"] = historical
    providers["Local IOC index"] = {"status": snapshot["status"], "snapshot_at": snapshot.get("snapshot_at")}
    providers["RDAP / WHOIS"] = {"status": {"confirmed": "Confirmed", "unavailable": "Unavailable", "not_applicable": "Not applicable"}[whois["registration_status"]]}
    return {
        **result,
        "case_id": case_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "kind": "url",
        "executive_summary": (
            coverage["detail"] if verdict in {"INCONCLUSIVE", "CLEAN"}
            else f"{verdict.title()} based on {len(result['evidence'])} evidence item(s)."
        ),
        "reputation_coverage": coverage,
        "domain_age": registration_label(whois),
        "registrar": whois["registrar"],
        "target": safe_target(target),
        "summary": result,
        "forensics": {"whois": whois},
        "providers": providers,
        "dataset_model": model,
        "ai_advisory": analyst.get("advisory"),
        "scan_metadata": {
            "scan_duration_ms": round((time.monotonic() - started) * 1000),
            "engine_version": VERSION,
            "mode": "passive",
            "whitelist_fast_path": allowlisted,
            "api_credits_used": 0 if allowlisted else None,
        },
        "engines": feeds,
        "recommendations": recommendations(verdict),
        "soc_arsenal": generate_blue_team_arsenal(domain),
        "siem_event": siem_event(case_id, domain, result),
    }


def investigate_html(html: str, context: str | None) -> dict:
    started = time.monotonic()
    target = normalize_target(context, resolve=False) if context else None
    page, findings = inspect_html(html, target["url"] if target else None)
    result = assess(findings, coverage_sufficient=False)
    return {
        **result,
        "case_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "kind": "html",
        "dom_forensics": page,
        "scan_metadata": {"mode": "offline", "scan_duration_ms": round((time.monotonic() - started) * 1000)},
        "target": safe_target(target) if target else {},
        "recommendations": recommendations(result["verdict"]),
    }
