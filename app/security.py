import re
import html
import socket
import ipaddress
from urllib.parse import urlparse

BLOCKED_HOSTNAMES = {
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "metadata.google.internal", "metadata", "169.254.169.254", "0.0.0.0"
}

PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"system\s*prompt",
    r"you\s+are\s+now",
    r"disregard\s+all",
    r"mark\s+this\s+as\s+clean",
    r"verdict\s*[:=]\s*clean",
    r"risk_score\s*[:=]\s*0"
]

WAF_ATTACK_PATTERNS = [
    r"<\s*script",
    r"javascript\s*:",
    r"onerror\s*=",
    r"onload\s*=",
    r"<\s*iframe",
    r"<\s*svg",
    r"file://",
    r"gopher://",
    r"dict://",
    r"ldap://"
]

def is_ip_unsafe(ip_str: str) -> bool:
    """Strictly validates that an IPv4/IPv6 address is strictly public/global."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if hasattr(ip_obj, "ipv4_mapped") and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped
        return (
            not ip_obj.is_global
            or ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
            or str(ip_obj).startswith("169.254.")
            or str(ip_obj).startswith("100.64.")
        )
    except ValueError:
        return True

def sanitize_for_llm(text: str) -> tuple[str, bool]:
    """Strips prompt injection attempts and neutralizes control characters before LLM analysis."""
    if not text:
        return "", False
    cleaned = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", text)
    injection_detected = False
    for pat in PROMPT_INJECTION_PATTERNS:
        if re.search(pat, cleaned, flags=re.IGNORECASE):
            injection_detected = True
            cleaned = re.sub(pat, "[REDACTED_PROMPT_INJECTION]", cleaned, flags=re.IGNORECASE)
    return html.escape(cleaned[:300]), injection_detected

def normalize_target(raw_input: str) -> dict:
    """WAF-grade input validator, SSRF guard, and URL normalizer."""
    if not raw_input or len(raw_input.strip()) > 2048:
        raise ValueError("Invalid target length (must be 1-2048 characters).")

    raw_trimmed = raw_input.strip()
    waf_triggered = any(re.search(p, raw_trimmed, re.IGNORECASE) for p in WAF_ATTACK_PATTERNS)
    if waf_triggered:
        raise ValueError("WAF Block: Malicious XSS, dangerous URI scheme, or script injection payload rejected.")

    cleaned = raw_trimmed.replace("[.]", ".").replace("hxxps://", "https://").replace("hxxp://", "http://")
    if not cleaned.startswith(("http://", "https://")):
        url = "https://" + cleaned
    else:
        url = cleaned

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("WAF Block: Only HTTP and HTTPS protocols are permitted.")

    domain = (parsed.hostname or "").lower().strip(".")
    if not domain or domain in BLOCKED_HOSTNAMES or domain.endswith((".local", ".internal", ".lan", ".arpa")):
        raise ValueError("SSRF Guard Block: Internal, loopback, or cloud metadata hostnames are strictly forbidden.")

    # Strict hostname character check (prevents command/header injection)
    if not re.match(r"^[a-z0-9.\-_]+$", domain):
        raise ValueError("WAF Block: Invalid characters in target hostname.")

    path = html.escape(parsed.path or "/")
    query = html.escape(parsed.query or "")

    resolved_ip = None
    ssrf_blocked = False

    try:
        # Check if user entered a direct IP
        ip_obj = ipaddress.ip_address(domain)
        resolved_ip = str(ip_obj)
        if is_ip_unsafe(resolved_ip):
            raise ValueError(f"SSRF Guard Block: Private, loopback, or reserved IP ({resolved_ip}) is forbidden.")
    except ValueError as e:
        if "SSRF Guard Block" in str(e):
            raise
        # Resolve domain all A/AAAA records and verify NONE point to internal/private IPs
        try:
            addr_info = socket.getaddrinfo(domain, None)
            all_ips = list({item[4][0] for item in addr_info if item[4]})
            for candidate_ip in all_ips:
                if is_ip_unsafe(candidate_ip):
                    raise ValueError(f"SSRF DNS Rebinding Block: Domain resolves to restricted internal IP ({candidate_ip}).")
            resolved_ip = all_ips[0] if all_ips else None
        except ValueError:
            raise
        except Exception:
            resolved_ip = None

    _, prompt_inj = sanitize_for_llm(raw_trimmed)

    return {
        "original_input": html.escape(raw_trimmed),
        "url": url,
        "domain": domain,
        "path": path,
        "query": query,
        "resolved_ip": resolved_ip,
        "ssrf_blocked": ssrf_blocked,
        "prompt_injection_attempted": prompt_inj
    }

def defang_ioc(url: str, domain: str, ip: str = None) -> dict:
    safe_url = html.escape(url.replace("https://", "hxxps://").replace("http://", "hxxp://").replace(".", "[.]"))
    safe_domain = html.escape(domain.replace(".", "[.]"))
    safe_ip = html.escape(ip.replace(".", "[.]")) if ip else "N/A"
    return {
        "defanged_url": safe_url,
        "defanged_domain": safe_domain,
        "defanged_ip": safe_ip
    }
