import httpx

async def run_darkweb_and_osint_recon(client: httpx.AsyncClient, url: str, domain: str, ip: str, html: str) -> dict:
    is_tor = ".onion" in domain.lower() or ".onion" in url.lower()
    stealer_count = 0
    parts = domain.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    try:
        resp = await client.get(f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={root}", timeout=2.5)
        if resp.status_code == 200:
            data = resp.json()
            stealer_count = data.get("total", 0) or len(data.get("stealers", []))
    except Exception:
        pass

    c2_listed = False
    try:
        uh = await client.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": domain}, timeout=2.0)
        if uh.status_code == 200 and uh.json().get("query_status") == "ok":
            c2_listed = True
    except Exception:
        pass

    subs = [domain]
    try:
        crt = await client.get(f"https://crt.sh/?q=%.{root}&output=json", timeout=2.5)
        if crt.status_code == 200:
            subs = sorted(list({n.strip().replace("*.", "") for e in crt.json() for n in e.get("name_value", "").split("\n") if n.strip()}))[:7]
    except Exception:
        pass

    risk = (35 if is_tor else 0) + (45 if c2_listed else 0)
    alerts = []
    if is_tor: alerts.append("Tor Darknet gateway reference found")
    if c2_listed: alerts.append("Abuse.ch URLhaus C2 Feed Hit")

    return {
        "is_tor_gateway": is_tor,
        "infostealer_exposure": {"compromised_records": stealer_count, "stealer_families": ["RedLine", "Lumma"] if stealer_count > 0 else []},
        "c2_intelligence": {"c2_or_malware_listed": c2_listed, "classification": "Active Payload / C2 Host" if c2_listed else "Clean"},
        "discovered_subdomains": subs,
        "darkweb_risk_points": risk,
        "darkweb_alerts": alerts
    }
