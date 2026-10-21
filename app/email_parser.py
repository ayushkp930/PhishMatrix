import re
from email import message_from_string

def analyze_raw_email(raw_email: str) -> dict:
    """Parses raw email headers and body to detect SPF/DKIM/DMARC spoofing and embedded phishing links."""
    msg = message_from_string(raw_email)
    from_hdr = msg.get("From", "Unknown Sender")
    return_path = msg.get("Return-Path", from_hdr)
    reply_to = msg.get("Reply-To", from_hdr)
    subject = msg.get("Subject", "No Subject")
    auth_results = msg.get("Authentication-Results", "").lower()

    spf_status = "FAIL / SPOOFED" if "spf=fail" in auth_results or "spf=softfail" in auth_results else ("PASS" if "spf=pass" in auth_results else "UNVERIFIED")
    dkim_status = "FAIL" if "dkim=fail" in auth_results else ("PASS" if "dkim=pass" in auth_results else "UNVERIFIED")
    dmarc_status = "FAIL" if "dmarc=fail" in auth_results else ("PASS" if "dmarc=pass" in auth_results else "UNVERIFIED")

    # Extract sender domain vs return-path domain mismatch
    from_domain = re.findall(r"@([A-Za-z0-9.-]+)", from_hdr)
    rp_domain = re.findall(r"@([A-Za-z0-9.-]+)", return_path)
    header_mismatch = bool(from_domain and rp_domain and from_domain[0].lower() != rp_domain[0].lower())

    # Extract IP hops and URLs
    hop_ips = list(set(re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", raw_email)))
    urls = list(set(re.findall(r"https?://[^\s'\"<>)\]]+", raw_email)))

    risk = 0
    alerts = []
    if spf_status.startswith("FAIL") or dmarc_status == "FAIL":
        risk += 45
        alerts.append("Email Authentication Failed (SPF/DMARC): High likelihood of sender spoofing")
    if header_mismatch:
        risk += 35
        alerts.append(f"Header Spoofing Mismatch: 'From' ({from_domain[0]}) does not match 'Return-Path' ({rp_domain[0]})")
    if urls:
        risk += 20
        alerts.append(f"Extracted {len(urls)} embedded URL(s) from email body for deep triage")

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
        "alerts": alerts
    }
