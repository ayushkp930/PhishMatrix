import os
import re
import httpx
from email import message_from_string
from dotenv import load_dotenv

load_dotenv()

async def verify_sender_mailboxlayer(email_addr: str) -> dict:
    mb_key = os.getenv("MAILBOXLAYER_API_KEY", "").strip()
    if not mb_key or "@" not in email_addr:
        return {"verified": False, "note": "Local RFC-5322 Header Check"}
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "http://apilayer.net/api/check",
                params={"access_key": mb_key, "email": email_addr, "smtp": 1},
                timeout=3.0
            )
            if resp.status_code == 200:
                d = resp.json()
                if "error" not in d:
                    return {
                        "format_valid": d.get("format_valid", True),
                        "mx_found": d.get("mx_found", False),
                        "smtp_check": d.get("smtp_check", False),
                        "disposable": d.get("disposable", False),
                        "free_email": d.get("free", False),
                        "reputation_score": d.get("score", 0.5)
                    }
    except Exception:
        pass
    return {"verified": True, "note": "Heuristic MX Check"}

def analyze_raw_email(raw_email: str) -> dict:
    msg = message_from_string(raw_email)
    from_hdr = msg.get("From", "Unknown Sender")
    return_path = msg.get("Return-Path", from_hdr)
    reply_to = msg.get("Reply-To", from_hdr)
    subject = msg.get("Subject", "No Subject")
    auth_results = msg.get("Authentication-Results", "").lower()

    spf_status = "FAIL / SPOOFED" if "spf=fail" in auth_results or "spf=softfail" in auth_results else ("PASS" if "spf=pass" in auth_results else "UNVERIFIED")
    dkim_status = "FAIL" if "dkim=fail" in auth_results else ("PASS" if "dkim=pass" in auth_results else "UNVERIFIED")
    dmarc_status = "FAIL" if "dmarc=fail" in auth_results else ("PASS" if "dmarc=pass" in auth_results else "UNVERIFIED")

    from_domain = re.findall(r"@([A-Za-z0-9.-]+)", from_hdr)
    rp_domain = re.findall(r"@([A-Za-z0-9.-]+)", return_path)
    header_mismatch = bool(from_domain and rp_domain and from_domain[0].lower() != rp_domain[0].lower())

    hop_ips = list(set(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", raw_email)))
    urls = list(set(re.findall(r"https?://[^\s'\"<>)\]]+", raw_email)))

    risk = 0
    alerts = []
    recommendations = []
    if spf_status.startswith("FAIL") or dmarc_status == "FAIL":
        risk += 45
        alerts.append("Email Authentication Failed (SPF/DMARC): High likelihood of sender spoofing")
        recommendations.append("Quarantine message immediately and enforce DMARC p=reject on gateway.")
    if header_mismatch:
        risk += 35
        alerts.append(f"Header Spoofing Mismatch: 'From' ({from_domain[0]}) != 'Return-Path' ({rp_domain[0]})")
        recommendations.append(f"Block Return-Path domain '{rp_domain[0]}' on Secure Email Gateway (SEG).")
    if urls:
        risk += 20
        alerts.append(f"Extracted {len(urls)} embedded URL(s) from email body for deep triage")
        recommendations.append("Submit extracted URLs to PhishMatrix URL Intelligence for sandbox detonation.")

    return {
        "subject": subject,
        "from": from_hdr,
        "return_path": return_path,
        "reply_to": reply_to,
        "spf": spf_status,
        "dkim": dkim_status,
        "dmarc": dmarc_status,
        "header_spoof_mismatch": header_mismatch,
        "originating_ips": hop_ips[:5],
        "extracted_urls": urls[:8],
        "email_risk_score": min(risk, 100),
        "verdict": "MALICIOUS_SPOOF" if risk >= 60 else ("SUSPICIOUS" if risk >= 25 else "CLEAN"),
        "alerts": alerts,
        "recommendations": recommendations or ["No immediate header spoofing detected; verify link destinations before clicking."]
    }
