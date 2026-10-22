import os
import time
from collections import defaultdict
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
from app.orchestrator import investigate_target
from app.email_parser import analyze_raw_email
from app.security import HoneypotTrapTriggered

app = FastAPI(
    title="PhishMatrix v5.0 // Hardened Enterprise SOAR & Active Deception Platform",
    description="16-Engine Threat Intel + 1,000+ Domain Whitelist + Active Deception Honeypot + 12 Blue-Team Rules",
    version="5.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

RATE_LIMIT_BUCKETS = defaultdict(list)

@app.middleware("http")
async def security_headers_and_waf_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    RATE_LIMIT_BUCKETS[client_ip] = [t for t in RATE_LIMIT_BUCKETS[client_ip] if now - t < 60]
    if len(RATE_LIMIT_BUCKETS[client_ip]) >= 35:
        return JSONResponse(
            status_code=429,
            content={
                "honeypot_triggered": True,
                "taunt_title": "LOL 😂 Slow Down! Rate-Limit Honeypot Triggered! 🍯🐢",
                "attack_type": "Automated DDoS / Brute-Force Scraping",
                "payload": f"{len(RATE_LIMIT_BUCKETS[client_ip])} requests/min from {client_ip}",
                "detail": "LOL 😂 Trying to flood the API? Take a breather, hacker! 🍯🤡"
            }
        )
    RATE_LIMIT_BUCKETS[client_ip].append(now)

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' https:; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://fonts.gstatic.com;"
    )
    return response

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

SCAN_CACHE = {}
CACHE_TTL_SECONDS = 600

class ScanRequest(BaseModel):
    url: str

class EmailScanRequest(BaseModel):
    raw_email: str

class BulkScanRequest(BaseModel):
    urls: List[str]

@app.get("/")
async def serve_ui():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))

# Decoy Honeypot Endpoints for nosey friends/scanners trying /admin, /.env, /wp-admin
@app.get("/admin")
@app.get("/.env")
@app.get("/wp-admin")
@app.get("/config.json")
async def decoy_honeypot_routes(request: Request):
    return JSONResponse(
        status_code=418,
        content={
            "honeypot_triggered": True,
            "status": "418 I'm a Teapot (Active Deception Honeypot)",
            "message": "LOL 😂 Nice try! Looking for secrets or /admin? You just walked straight into the PhishMatrix Honeypot! 🍯🤡🚨",
            "Path_Probed": str(request.url.path)
        }
    )

@app.post("/api/v1/scan")
async def api_scan_url(req: ScanRequest, request: Request):
    key = req.url.strip().lower()
    if not key:
        raise HTTPException(status_code=400, detail="Target URL cannot be empty")
    now = time.time()
    if key in SCAN_CACHE and (now - SCAN_CACHE[key]["ts"] < CACHE_TTL_SECONDS):
        cached = SCAN_CACHE[key]["data"]
        cached["scan_metadata"]["cached"] = True
        return cached
    try:
        result = await investigate_target(req.url.strip())
    except HoneypotTrapTriggered as trap:
        return JSONResponse(
            status_code=418,
            content={
                "honeypot_triggered": True,
                "taunt_title": "LOL 😂 Nice Try! You Triggered the PhishMatrix Honeypot! 🍯🤡",
                "attack_type": trap.attack_type,
                "payload": trap.payload,
                "detail": trap.message
            }
        )
    except ValueError as sec_err:
        return JSONResponse(
            status_code=418,
            content={
                "honeypot_triggered": True,
                "taunt_title": "LOL 😂 Nice Try! Blocked by PhishMatrix Honeypot! 🍯🤡",
                "attack_type": "WAF Security Policy Violation",
                "payload": req.url[:100],
                "detail": str(sec_err)
            }
        )
    SCAN_CACHE[key] = {"ts": now, "data": result}
    return result

@app.post("/api/v1/email-scan")
async def api_scan_email(req: EmailScanRequest):
    if not req.raw_email.strip():
        raise HTTPException(status_code=400, detail="Email content cannot be empty")
    return analyze_raw_email(req.raw_email[:50000])

@app.post("/api/v1/bulk-scan")
async def api_bulk_scan(req: BulkScanRequest):
    targets = [u.strip() for u in req.urls if u.strip()][:8]
    results = []
    for u in targets:
        try:
            results.append(await investigate_target(u))
        except Exception as e:
            results.append({
                "target": {"domain": u[:60], "resolved_ip": "HONEYPOT_TRAP"},
                "summary": {"risk_score": 100, "verdict": "LOL_HONEYPOT_😂🍯"},
                "heuristics": {"impersonated_brand": str(e)}
            })
    return {"count": len(results), "results": results}

@app.get("/cli", response_class=PlainTextResponse)
async def kali_terminal_cli(url: str = Query(..., description="Target URL or domain to scan from terminal")):
    try:
        res = await investigate_target(url)
    except HoneypotTrapTriggered as trap:
        return f"""
╔══════════════════════════════════════════════════════════════════════════╗
║  🍯 LOL 😂 NICE TRY! PHISHMATRIX ACTIVE DECEPTION HONEYPOT TRIGGERED! 🤡 ║
╚══════════════════════════════════════════════════════════════════════════╝
  • Attack Detected : {trap.attack_type}
  • Captured Input  : {trap.payload}
  • Verdict         : {trap.message}
"""
    except ValueError as sec_err:
        return f"[🍯 HONEYPOT SHIELD]: LOL 😂 {sec_err}\n"

    s = res["summary"]
    t = res["target"]
    w = res["forensics"]["whois"]
    vt = res["engines"]["virustotal"]
    ab = res["engines"]["abuseipdb"]
    ai = res["ai_council"]

    color = "\033[91m" if s["verdict"] == "MALICIOUS" else ("\033[93m" if s["verdict"] == "SUSPICIOUS" else "\033[92m")
    reset = "\033[0m"
    cyan = "\033[96m"

    triggers_str = "\n".join(f"  [!] {tr}" for tr in s["triggers"][:6]) or "  [✓] Zero malicious indicators triggered (Verified Safe)."
    return f"""
{cyan}╔══════════════════════════════════════════════════════════════════════════╗
║   PHISHMATRIX v5.0 // KALI LINUX TERMINAL THREAT INVESTIGATION ENGINE    ║
╚══════════════════════════════════════════════════════════════════════════╝{reset}
  • Target URL     : {t['defanged_url']}
  • Resolved IP    : {t['resolved_ip']} ({ab['isp']} / {ab['country']} / {ab['asn']})
  • Domain Age     : {w['creation_date']} ({w['domain_age_days'] if w['domain_age_days'] is not None else 'Established'} days) | Registrar: {w['registrar']}
  • Unified Score  : {color}{s['risk_score']}/100 [{s['verdict']}]{reset}
  • VirusTotal v3  : {vt['malicious']}/{vt['total_engines']} ({vt['source_mode']})
  • AbuseIPDB Risk : {ab['confidence_score']}% Confidence ({ab['total_reports']} reports)

{cyan}[+] DETECTION TRIGGERS & FORENSIC EVIDENCE:{reset}
{triggers_str}

{cyan}[+] AI SOC THREAT ANALYST ({ai.get('active_model_used', 'Autonomous')}):{reset}
  {ai['executive_soc_summary']}
{cyan}════════════════════════════════════════════════════════════════════════════{reset}
"""
