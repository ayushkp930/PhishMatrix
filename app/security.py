import re
import html
import socket
import ipaddress
from urllib.parse import urlparse, unquote

class HoneypotTrapTriggered(ValueError):
    """Raised when an attacker or tester attempts XSS, SQLi, SSRF, RCE, or Prompt Injection."""
    def __init__(self, attack_type: str, payload: str, message: str):
        super().__init__(message)
        self.attack_type = attack_type
        self.payload = html.escape(payload[:180])
        self.message = message

BLOCKED_HOSTNAMES = {
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "metadata.google.internal", "metadata", "169.254.169.254", "0.0.0.0",
    "127.0.0.1", "::1", "internal", "intranet"
}

PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above|system)\s+instructions",
    r"system\s*prompt",
    r"you\s+are\s+now",
    r"disregard\s+all",
    r"mark\s+this\s+as\s+clean",
    r"verdict\s*[:=]\s*clean",
    r"risk_score\s*[:=]\s*0",
    r"forget\s+everything"
]

ATTACK_SIGNATURES = [
    ("Cross-Site Scripting (XSS) Payload", r"(<\s*script|javascript\s*:|onerror\s*=|onload\s*=|onmouseover\s*=|<\s*iframe|<\s*svg|<\s*img|alert\s*\(|document\.cookie|String\.fromCharCode)"),
    ("SQL Injection (SQLi) Probe", r"(\bunion\s+select\b|\bor\s+1\s*=\s*1\b|\band\s+1\s*=\s*1\b|'\s*or\s*'|admin'\s*--|sleep\s*\(\s*\d+\s*\)|information_schema)"),
    ("OS Command Injection / RCE Probe", r"(;\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b|\|\|\s*(id|whoami)|`[^`]+`|\$\([^)]+\)|/etc/passwd|/etc/shadow|cmd\.exe|powershell\.exe)"),
    ("Directory / Path Traversal Probe", r"(\.\./\.\./|\.\.\\\.\.\\|%2e%2e%2f|/proc/self/)"),
    ("Forbidden SSRF Protocol Scheme", r"^(file|gopher|dict|ldap|ftp|ssh|telnet|sftp|tftp|jar|netdoc)://"),
    ("Server-Side Template Injection (SSTI)", r"(\{\{.*\}\}|\$\{.*\})")
]

def is_ip_unsafe(ip_str: str) -> bool:
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
            or str(ip_obj).startswith("127.")
            or str(ip_obj) == "0.0.0.0"
        )
    except ValueError:
        return True

def sanitize_for_llm(text: str) -> tuple[str, bool]:
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
    if not raw_input or len(raw_input.strip()) > 2048:
        raise HoneypotTrapTriggered("Buffer / Length Overflow Attempt", str(raw_input)[:80], "LOL 😂 Nice try! Payload length overflow blocked by PhishMatrix Honeypot! 🍯🤡")

    raw_trimmed = raw_input.strip()
    decoded_once = unquote(raw_trimmed)
    combined_check = f"{raw_trimmed} {decoded_once}"

    # 1. Check Active Honeypot Attack Signatures (XSS, SQLi, RCE, Traversal, SSTI)
    for attack_label, pattern in ATTACK_SIGNATURES:
        if re.search(pattern, combined_check, flags=re.IGNORECASE):
            raise HoneypotTrapTriggered(
                attack_label,
                raw_trimmed,
                f"LOL 😂 Nice Try! {attack_label} intercepted by PhishMatrix Active Deception Honeypot! 🍯🤡"
            )

    # 2. Check AI Prompt Injection inside URL
    _, prompt_inj = sanitize_for_llm(combined_check)
    if prompt_inj:
        raise HoneypotTrapTriggered(
            "AI / LLM Prompt Injection Attempt",
            raw_trimmed,
            "LOL 😂 Trying to brainwash our AI Analyst? Prompt Injection caught in the Honeypot! 🍯🤖🤡"
        )

    cleaned = raw_trimmed.replace("[.]", ".").replace("hxxps://", "https://").replace("hxxp://", "http://")
    url = cleaned if cleaned.startswith(("http://", "https://")) else "https://" + cleaned

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HoneypotTrapTriggered("Forbidden URI Scheme", raw_trimmed, "LOL 😂 Only HTTP/HTTPS allowed! Nice try! 🍯🤡")

    domain = (parsed.hostname or "").lower().strip(".")
    if not domain or domain in BLOCKED_HOSTNAMES or domain.endswith((".local", ".internal", ".lan", ".arpa", ".localhost")):
        raise HoneypotTrapTriggered(
            "Server-Side Request Forgery (SSRF) Probe",
            raw_trimmed,
            f"LOL 😂 Trying to scan internal/loopback host ({domain or 'local'})? Welcome to the SSRF Honeypot! 🍯🤡"
        )

    # Check octal/hex/decimal IP obfuscation tricks (e.g., 2130706433 or 0x7f000001)
    if re.match(r"^(0x[0-9a-f]+|\d{8,10}|0\d+\.0\d+.*)$", domain):
        raise HoneypotTrapTriggered(
            "SSRF IP Obfuscation (Hex/Octal/Dword)",
            raw_trimmed,
            "LOL 😂 Hex/Decimal IP encoding trick spotted! Our SSRF Guard knows that old trick! 🍯🤡"
        )

    if not re.match(r"^[a-z0-9.\-_]+$", domain):
        raise HoneypotTrapTriggered(
            "Malformed Hostname / Injection Probe",
            raw_trimmed,
            "LOL 😂 Invalid hostname characters blocked by PhishMatrix Honeypot! 🍯🤡"
        )

    path = html.escape(parsed.path or "/")
    query = html.escape(parsed.query or "")

    resolved_ip = None
    try:
        ip_obj = ipaddress.ip_address(domain)
        resolved_ip = str(ip_obj)
        if is_ip_unsafe(resolved_ip):
            raise HoneypotTrapTriggered(
                "SSRF Internal / Cloud Metadata IP Probe",
                raw_trimmed,
                f"LOL 😂 Private/Loopback/Metadata IP ({resolved_ip}) blocked! No AWS/GCP keys for you today! 🍯🤡"
            )
    except ValueError as e:
        if isinstance(e, HoneypotTrapTriggered):
            raise
        try:
            addr_info = socket.getaddrinfo(domain, None)
            all_ips = list({item[4][0] for item in addr_info if item[4]})
            for candidate_ip in all_ips:
                if is_ip_unsafe(candidate_ip):
                    raise HoneypotTrapTriggered(
                        "DNS Rebinding / Internal SSRF Attempt",
                        raw_trimmed,
                        f"LOL 😂 DNS Rebinding to internal IP ({candidate_ip}) caught red-handed! 🍯🤡"
                    )
            resolved_ip = all_ips[0] if all_ips else None
        except HoneypotTrapTriggered:
            raise
        except Exception:
            resolved_ip = None

    return {
        "original_input": html.escape(raw_trimmed),
        "url": url,
        "domain": domain,
        "path": path,
        "query": query,
        "resolved_ip": resolved_ip,
        "ssrf_blocked": False,
        "prompt_injection_attempted": False
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
