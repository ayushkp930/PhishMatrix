import os
import time
import asyncio
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
from app.orchestrator import investigate_target
from app.email_parser import analyze_raw_email

app = FastAPI(
    title="PhishMatrix // AI-Powered Multi-Engine Threat Investigation Platform",
    description="8-Feed Threat Intel + 3-Model AI SOC Council + Zero-Day DOM/WHOIS/DarkWeb Forensics",
    version="3.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# In-Memory TTL Cache to save API Quotas & boost speed
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

@app.post("/api/v1/scan")
async def api_scan_url(req: ScanRequest):
    key = req.url.strip().lower()
    if not key:
        raise HTTPException(status_code=400, detail="Target URL cannot be empty")
    now = time.time()
    if key in SCAN_CACHE and (now - SCAN_CACHE[key]["ts"] < CACHE_TTL_SECONDS):
        cached = SCAN_CACHE[key]["data"]
        cached["scan_metadata"]["cached"] = True
        return cached

    result = await investigate_target(req.url.strip())
    SCAN_CACHE[key] = {"ts": now, "data": result}
    return result

@app.post("/api/v1/email-scan")
async def api_scan_email(req: EmailScanRequest):
    if not req.raw_email.strip():
        raise HTTPException(status_code=400, detail="Email content cannot be empty")
    return analyze_raw_email(req.raw_email)

@app.post("/api/v1/bulk-scan")
async def api_bulk_scan(req: BulkScanRequest):
    targets = [u.strip() for u in req.urls if u.strip()][:8]
    results = await asyncio.gather(*(investigate_target(u) for u in targets))
    return {"count": len(results), "results": results}

@app.get("/cli", response_class=PlainTextResponse)
async def kali_terminal_cli(url: str = Query(..., description="Target URL or domain to scan from terminal")):
    """Kali Linux Terminal Direct Mode: curl -s 'https://your-app.vercel.app/cli?url=evil.com'"""
    res = await investigate_target(url)
    s = res["summary"]
    t = res["target"]
    w = res["forensics"]["whois"]
    vt = res["engines"]["virustotal"]
    ab = res["engines"]["abuseipdb"]
    ai = res["ai_council"]

    color = "\033[91m" if s["verdict"] == "MALICIOUS" else ("\033[93m" if s["verdict"] == "SUSPICIOUS" else "\033[92m")
    reset = "\033[0m"
    cyan = "\033[96m"

    triggers_str = "\n".join(f"  [!] {tr}" for tr in s["triggers"][:6]) or "  [✓] No malicious indicators triggered."
    out = f"""
{cyan}╔══════════════════════════════════════════════════════════════════════════╗
║   PHISHMATRIX v3.0 // KALI LINUX TERMINAL THREAT INVESTIGATION ENGINE    ║
╚══════════════════════════════════════════════════════════════════════════╝{reset}
  • Target URL     : {t['defanged_url']}
  • Resolved IP    : {t['resolved_ip']} ({ab['isp']} / {ab['country']} / {ab['asn']})
  • Domain Age     : {w['creation_date']} ({w['domain_age_days'] if w['domain_age_days'] is not None else 'Established'} days) | Registrar: {w['registrar']}
  • Unified Score  : {color}{s['risk_score']}/100 [{s['verdict']}]{reset}
  • VirusTotal v3  : {vt['malicious']}/{vt['total_engines']} vendors flagged malicious
  • AbuseIPDB Risk : {ab['confidence_score']}% Confidence ({ab['total_reports']} reports)

{cyan}[+] DETECTION TRIGGERS & FORENSIC EVIDENCE:{reset}
{triggers_str}

{cyan}[+] 3-MODEL AI SOC COUNCIL CONSENSUS:{reset}
  {ai['executive_soc_summary']}

{cyan}════════════════════════════════════════════════════════════════════════════{reset}
"""
    return out
