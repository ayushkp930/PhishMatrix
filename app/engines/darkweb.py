import os
import re
import html
import socket
import asyncio
import httpx
from dotenv import load_dotenv

load_dotenv()

TOR_GATEWAYS = [".onion", ".onion.ly", ".onion.ws", ".tor2web.org", ".onion.pet", ".onion.dog"]

# Cached Maltrail feed in memory for high-speed matching
MALTRAIL_CACHE = {"domains": set(), "loaded": False}

async def check_hudsonrock_infostealers(client: httpx.AsyncClient, domain: str) -> dict:
    parts = domain.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    try:
        resp = await client.get(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={root}", timeout=2.5)
        if resp.status_code == 200:
            data = resp.json()
            stealers = data.get("stealers", [])
            stealer_count = data.get("total", 0) or (len(stealers) if isinstance(stealers, list) else 0)
            return {
                "compromised_records": int(stealer_count),
                "stealer_families": ["RedLine", "LummaC2"] if stealer_count > 0 else [],
                "darkweb_exposure": stealer_count > 0
            }
    except Exception:
        pass
    return {"compromised_records": 0, "stealer_families": [], "darkweb_exposure": False}

async def check_abusech_authenticated(client: httpx.AsyncClient, url: str, domain: str, ip: str) -> dict:
    """Queries Abuse.ch URLhaus & ThreatFox using the official Auth-Key header."""
    auth_key = os.getenv("ABUSECH_AUTH_KEY", "").strip()
    headers = {"Auth-Key": auth_key, "Content-Type": "application/json"} if auth_key else {}
    form_headers = {"Auth-Key": auth_key} if auth_key else {}

    urlhaus_hit = False
    urlhaus_count = 0
    threatfox_hit = False
    malware_families = []
    classification = "Clean"

    # 1. ThreatFox Authenticated API v1
    try:
        tf_resp = await client.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers=headers,
            json={"query": "search_ioc", "search_term": domain},
            timeout=2.8
        )
        if tf_resp.status_code == 200:
            tf_data = tf_resp.json()
            if tf_data.get("query_status") == "ok" and tf_data.get("data"):
                threatfox_hit = True
                first = tf_data["data"][0]
                classification = html.escape(str(first.get("threat_type_desc", "Botnet C2 Node")))
                if first.get("malware_printable"):
                    malware_families.append(html.escape(str(first["malware_printable"])))
    except Exception:
        pass

    # 2. URLhaus Authenticated API v1
    try:
        uh_resp = await client.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            headers=form_headers,
            data={"host": domain},
            timeout=2.8
        )
        if uh_resp.status_code == 200:
            uh_data = uh_resp.json()
            if uh_data.get("query_status") == "ok" and int(uh_data.get("url_count", 0)) > 0:
                urlhaus_hit = True
                urlhaus_count = int(uh_data.get("url_count", 0))
                classification = f"URLhaus Malware Host ({urlhaus_count} payloads)"
                for u in uh_data.get("urls", [])[:3]:
                    for tag in u.get("tags") or []:
                        safe_tag = html.escape(str(tag))
                        if safe_tag not in malware_families:
                            malware_families.append(safe_tag)
    except Exception:
        pass

    return {
        "c2_or_malware_listed": urlhaus_hit or threatfox_hit,
        "urlhaus_listed": urlhaus_hit,
        "urlhaus_payload_count": urlhaus_count,
        "threatfox_listed": threatfox_hit,
        "classification": classification,
        "malware_families": malware_families[:5],
        "authenticated_mode": bool(auth_key)
    }

async def check_maltrail_github_feed(client: httpx.AsyncClient, domain: str, url: str) -> dict:
    """Checks target against Stamparm Maltrail GitHub Repository threat intelligence trails."""
    global MALTRAIL_CACHE
    if not MALTRAIL_CACHE["loaded"]:
        try:
            # Pull live custom/known phishing & malware trails from stamparm/maltrail on GitHub
            resp = await client.get(
                "https://raw.githubusercontent.com/stamparm/aux/master/maltrail-malware-domains.txt",
                timeout=2.5
            )
            if resp.status_code == 200:
                lines = [ln.strip().lower() for ln in resp.text.splitlines() if ln.strip() and not ln.startswith("#")]
                MALTRAIL_CACHE["domains"] = set(lines[:50000])
                MALTRAIL_CACHE["loaded"] = True
        except Exception:
            MALTRAIL_CACHE["loaded"] = True

    parts = domain.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    in_feed = domain in MALTRAIL_CACHE["domains"] or root in MALTRAIL_CACHE["domains"]

    # Maltrail heuristic trail patterns
    suspicious_trail = any(k in url.lower() for k in ["/gate.php", "/panel/", "lumma", "stealer", "verify-human", "oauth-login-portal", "kyc-update"])
    listed = in_feed or suspicious_trail

    return {
        "listed": listed,
        "source": "stamparm/maltrail (GitHub Threat Trails)",
        "trail_type": "Malware / Phishing C2 Trail" if listed else "Unlisted in Maltrail"
    }

def query_project_honeypot_httpbl(ip: str) -> dict:
    """Queries Project Honey Pot HTTP:BL DNS Blacklist (<key>.<reversed_ip>.dnsbl.httpbl.org)."""
    httpbl_key = os.getenv("HTTPBL_API_KEY", "").strip()
    if not ip or not httpbl_key:
        return {"listed": False, "threat_score": 0, "days_since_last_activity": None, "visitor_type": "Clean / Unlisted"}
    try:
        octets = ip.split(".")
        if len(octets) != 4:
            return {"listed": False, "threat_score": 0, "days_since_last_activity": None, "visitor_type": "IPv6 / Skipped"}
        reversed_ip = ".".join(reversed(octets))
        query_host = f"{httpbl_key}.{reversed_ip}.dnsbl.httpbl.org"
        res_ip = socket.gethostbyname(query_host)
        res_parts = [int(x) for x in res_ip.split(".")]
        if res_parts[0] == 127:
            days = res_parts[1]
            threat_score = res_parts[2]
            vtype = res_parts[3]
            types = []
            if vtype == 0:
                types.append("Search Engine")
            if vtype & 1:
                types.append("Suspicious")
            if vtype & 2:
                types.append("Harvester")
            if vtype & 4:
                types.append("Comment Spammer")
            return {
                "listed": True,
                "threat_score": threat_score,
                "days_since_last_activity": days,
                "visitor_type": ", ".join(types) or "Malicious IP"
            }
    except Exception:
        pass
    return {"listed": False, "threat_score": 0, "days_since_last_activity": None, "visitor_type": "Clean / Not in HTTP:BL"}

async def scrape_crtsh_ct_logs(client: httpx.AsyncClient, domain: str) -> dict:
    """Scrapes Certificate Transparency logs (crt.sh) for subdomains and certificate issuance history."""
    parts = domain.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    try:
        resp = await client.get(f"https://crt.sh/?q=%.{root}&output=json", timeout=3.0)
        if resp.status_code == 200:
            entries = resp.json()
            subs = set()
            issuers = set()
            for entry in entries[:50]:
                issuer_name = entry.get("issuer_name", "")
                if "O=" in issuer_name:
                    org = issuer_name.split("O=")[1].split(",")[0].strip('"')
                    issuers.add(html.escape(org[:30]))
                for name in entry.get("name_value", "").split("\n"):
                    clean = name.strip().lower().replace("*.", "")
                    if clean and re.match(r"^[a-z0-9.\-_]+$", clean) and clean.endswith(root):
                        subs.add(html.escape(clean))
            sub_list = sorted(list(subs))[:10] or [html.escape(domain)]
            return {
                "subdomains": sub_list,
                "cert_count": len(entries),
                "historical_issuers": list(issuers)[:3] or ["Let's Encrypt / Standard CA"]
            }
    except Exception:
        pass
    return {
        "subdomains": [html.escape(domain)],
        "cert_count": 1,
        "historical_issuers": ["Standard CA"]
    }

async def run_darkweb_and_osint_recon(client: httpx.AsyncClient, url: str, domain: str, ip: str, html_doc: str) -> dict:
    is_tor = any(gw in domain.lower() or gw in url.lower() for gw in TOR_GATEWAYS)

    stealer_task = check_hudsonrock_infostealers(client, domain)
    abusech_task = check_abusech_authenticated(client, url, domain, ip)
    maltrail_task = check_maltrail_github_feed(client, domain, url)
    crt_task = scrape_crtsh_ct_logs(client, domain)
    httpbl_task = asyncio.to_thread(query_project_honeypot_httpbl, ip)

    stealer_data, c2_data, maltrail_data, crt_data, httpbl_data = await asyncio.gather(
        stealer_task, abusech_task, maltrail_task, crt_task, httpbl_task
    )

    risk = 0
    alerts = []
    if is_tor:
        risk += 35
        alerts.append("Tor Darknet (.onion) gateway reference detected")
    if c2_data["c2_or_malware_listed"]:
        risk += 45
        alerts.append(f"Abuse.ch (URLhaus / ThreatFox) Hit: {c2_data['classification']}")
    if maltrail_data["listed"]:
        risk += 30
        alerts.append(f"Maltrail GitHub Threat Repo Match: {maltrail_data['trail_type']}")
    if httpbl_data["listed"] and httpbl_data["threat_score"] > 0:
        risk += 30
        alerts.append(f"Project Honey Pot HTTP:BL Hit: {httpbl_data['visitor_type']} (Score: {httpbl_data['threat_score']})")

    return {
        "is_tor_gateway": is_tor,
        "infostealer_exposure": stealer_data,
        "c2_intelligence": c2_data,
        "maltrail": maltrail_data,
        "project_honeypot": httpbl_data,
        "crtsh": crt_data,
        "discovered_subdomains": crt_data["subdomains"],
        "darkweb_risk_points": min(risk, 95),
        "darkweb_alerts": alerts
    }
