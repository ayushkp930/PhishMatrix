import asyncio
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from hashlib import sha256
from typing import Annotated
from uuid import uuid4

import httpx

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, StringConstraints

from app.engines.soc_generator import case_exports
from app.engines.legacy_intel import malshare_lookup
from app.email_parser import analyze_raw_email
from app.middleware import WorkbenchMiddleware
from app.orchestrator import investigate_html, investigate_target
from app.scoring import VERSION, catalogue, assess, finding
from app.security import HoneypotTrapTriggered, printable

load_dotenv()
LOG = logging.getLogger("phishmatrix")
# Some upstream providers require credentials in request parameters.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
STATIC = Path(__file__).resolve().parent.parent / "static"
URL = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2048)]
Text = Annotated[str, StringConstraints(min_length=1, max_length=50000)]
Html = Annotated[str, StringConstraints(min_length=1, max_length=65536)]
Targets = Annotated[list[URL], Field(min_length=1, max_length=8)]


app = FastAPI(
    title="PhishMatrix Evidence Workbench",
    description="Passive phishing triage and local artifact analysis",
    version=VERSION,
    docs_url=None,
    redoc_url=None,
)
app.add_middleware(WorkbenchMiddleware)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


class ScanRequest(BaseModel):
    url: URL


class HashLookupRequest(BaseModel):
    hash: Annotated[str, StringConstraints(strip_whitespace=True, to_lower=True, pattern=r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")]


class EmailScanRequest(BaseModel):
    raw_email: Text | None = None
    email: Text | None = None
    email_content: Text | None = None


class HtmlScanRequest(BaseModel):
    html: Html
    url: URL | None = None


class BulkScanRequest(BaseModel):
    urls: Targets | None = None
    indicators: Targets | None = None
    targets: Targets | None = None


@app.exception_handler(RequestValidationError)
async def invalid_request(request: Request, exc: RequestValidationError):
    return JSONResponse({"detail": "Invalid scan input or input limit exceeded."}, status_code=422)


@app.exception_handler(HoneypotTrapTriggered)
async def short_deception_response(request: Request, trap: HoneypotTrapTriggered):
    LOG.info("honeypot blocked category=%s", trap.attack_type)
    return JSONResponse(
        {"honeypot_triggered": True, "taunt_title": "LOL 😂 Nice try!", "attack_type": trap.attack_type, "detail": trap.message},
        status_code=418,
    )


@app.get("/health")
async def api_health():
    return {"status": "online", "version": VERSION, "mode": "passive", "waf": "active"}


@app.get("/")
async def serve_ui():
    return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})


@app.get("/api/v1/rules")
async def detection_catalogue():
    return {"ruleset_version": VERSION, "rules": catalogue()}


@app.get("/admin")
@app.get("/.env")
@app.get("/wp-admin")
@app.get("/config.json")
@app.get("/phpmyadmin")
async def decoy_honeypot_routes():
    raise HoneypotTrapTriggered("decoy route probe", "")


async def run_scan(request: Request, url: str) -> dict:
    state = request.app.state
    loop = asyncio.get_running_loop()
    if getattr(state, "scan_loop", None) is not loop:
        state.scan_loop = loop
        state.slots = asyncio.Semaphore(8)
    slots = state.slots
    try:
        await asyncio.wait_for(slots.acquire(), 0.5)
    except TimeoutError:
        raise HTTPException(status_code=503, detail="Scan workers are busy. Retry shortly.") from None
    try:
        async with asyncio.timeout(21):
            return await investigate_target(url)
    except HoneypotTrapTriggered:
        raise
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid URL, domain or IP.") from None
    except TimeoutError:
        raise HTTPException(status_code=504, detail="Scan deadline exceeded. Try again shortly.") from None
    finally:
        slots.release()


@app.post("/api/v1/scan")
async def api_scan_url(req: ScanRequest, request: Request):
    return await run_scan(request, req.url)


@app.post("/api/v1/hash-lookup")
async def api_lookup_hash(req: HashLookupRequest):
    async with httpx.AsyncClient(timeout=3.0, follow_redirects=False) as client:
        result = await malshare_lookup(client, req.hash)
    case_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    status = result["status"]
    findings = [finding("TI_HASH_LISTED", "MalShare", "The exact file digest appears in MalShare. Confirm file behavior before containment.")] if status == "Match" else []
    assessment = assess(findings, coverage_sufficient=False)
    return {
        "provider": "MalShare", **result, **assessment, "case_id": case_id, "kind": "hash", "timestamp": timestamp,
        "target": {"hash": req.hash}, "providers": {"MalShare": result},
        "executive_summary": f"MalShare metadata lookup: {status}.",
        **case_exports(case_id, timestamp, assessment, "hash", digest=req.hash),
    }


@app.post("/email-scan")
@app.post("/api/v1/email-scan")
async def api_scan_email(req: EmailScanRequest):
    started = time.monotonic()
    raw = req.raw_email or req.email or req.email_content
    if not raw or not raw.strip():
        raise HTTPException(status_code=400, detail="Email content cannot be empty.")
    result = await asyncio.to_thread(analyze_raw_email, raw)
    case_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    return {
        **result,
        "case_id": case_id, "timestamp": timestamp, "kind": "email",
        **case_exports(case_id, timestamp, result, "email", digest=sha256(raw.encode("utf-8")).hexdigest()),
        "scan_metadata": {"mode": "offline", "scan_duration_ms": round((time.monotonic() - started) * 1000)},
    }


@app.post("/api/v1/html-scan")
async def api_scan_html(req: HtmlScanRequest):
    try:
        return await asyncio.to_thread(investigate_html, req.html, req.url)
    except HoneypotTrapTriggered:
        raise
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid context URL.") from None


@app.post("/bulk-scan")
@app.post("/api/v1/bulk-scan")
async def api_bulk_scan(req: BulkScanRequest, request: Request):
    started = time.monotonic()
    targets = req.urls or req.indicators or req.targets
    if not targets:
        raise HTTPException(status_code=400, detail="Enter at least one indicator.")

    async def scan_item(index: int, url: str) -> dict:
        try:
            result = await run_scan(request, url)
            return {
                "position": index,
                "domain": result["target"]["domain"],
                "indicator": result["target"]["defanged_url"],
                "resolved_ip": result["target"]["resolved_ip"],
                "risk_score": result["risk_score"],
                "verdict": result["verdict"],
                "summary": result["summary"],
                "domain_age": result["domain_age"],
                "reputation_coverage": result["reputation_coverage"],
                "registration": result["forensics"]["whois"],
            }
        except HoneypotTrapTriggered as trap:
            LOG.info("honeypot blocked category=%s", trap.attack_type)
            return {"position": index, "verdict": "BLOCKED", "honeypot_triggered": True, "detail": trap.message}
        except HTTPException as error:
            return {"position": index, "verdict": "UNAVAILABLE", "detail": error.detail}

    results = await asyncio.gather(*(scan_item(index, url) for index, url in enumerate(targets, 1)))
    return {
        "kind": "bulk", "case_id": str(uuid4()), "timestamp": datetime.now(timezone.utc).isoformat(),
        "count": len(results), "results": results,
        "scan_metadata": {"mode": "passive", "scan_duration_ms": round((time.monotonic() - started) * 1000)},
    }


def cli_report(result: dict) -> str:
    target = result["target"]
    rows = [
        "PhishMatrix · Passive Investigation",
        f"Target: {target['defanged_url']}",
        f"Domain Age: {result['domain_age']}",
        f"Unified Score: {result['risk_score']}/100 [{result['verdict']}]",
        f"Case: {result['case_id']}",
        f"Coverage: {result['reputation_coverage']['detail']}",
        "",
        *[f"[{item['rule_id']}] {item['label']} — {item['detail']}" for item in result["evidence"]],
        *[f"{name}: {item['status']}" for name, item in result["providers"].items()],
    ]
    return "\n".join(printable(row, 1000) for row in rows) + "\n"


@app.get("/cli", response_class=PlainTextResponse)
async def kali_terminal_cli(request: Request, url: Annotated[str, Query(min_length=1, max_length=2048)]):
    return cli_report(await run_scan(request, url))


@app.post("/cli", response_class=PlainTextResponse)
async def terminal_scan(req: ScanRequest, request: Request):
    return cli_report(await run_scan(request, req.url))
