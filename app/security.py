import html
import ipaddress
import re
import socket
from urllib.parse import unquote, urlsplit, urlunsplit

import idna


class HoneypotTrapTriggered(ValueError):
    def __init__(self, attack_type: str, payload: str, message: str | None = None):
        self.attack_type = attack_type
        self.payload = ""  # Keep the legacy attribute without retaining submitted payloads.
        self.message = message or f"LOL 😂 Nice try! PhishMatrix honeypot blocked {attack_type}. 🍯"
        super().__init__(self.message)


BLOCKED_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".arpa", ".home")
PATTERNS = {
    "cross-site scripting": r"<\s*/?\s*(script|iframe|svg|img)\b|javascript\s*:|\bon(error|load)\s*=",
    "SQL injection": r"\bunion\s+select\b|['\"]\s*(or|and)\s+['\d].*?=|\bor\s+1\s*=\s*1\b",
    "command injection": r";\s*(cat|id|whoami|bash|curl)\b|\$\([^)]+\)",
    "path traversal probe": r"(?:\.\.[/\\]){2}|/etc/(?:passwd|shadow)",
    "template injection": r"\{\{[^}]+\}\}",
    "prompt injection": r"ignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions",
}
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")
AMBIGUOUS_IP = re.compile(r"(?:0x[\da-f]+|[0-9]+)(?:\.(?:0x[\da-f]+|[0-9]+)){0,3}", re.I)


def sanitize_for_llm(text: str) -> tuple[str, bool]:
    cleaned = CONTROL.sub(" ", text or "")
    cleaned, count = re.subn(PATTERNS["prompt injection"], "[redacted]", cleaned, flags=re.I)
    return html.escape(cleaned[:300]), bool(count)


def is_ip_unsafe(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        elif ip in ipaddress.ip_network("64:ff9b::/96") or ip.sixtofour or ip.teredo:
            return True
    return not ip.is_global or ip.is_multicast or ip.is_reserved


def normalize_target(raw_input: str, *, resolve: bool = True) -> dict:
    raw = raw_input.strip()
    if not raw or len(raw) > 2048:
        raise ValueError("Enter a URL, domain or IP up to 2,048 characters.")
    decoded = unquote(unquote(raw))
    for attack, pattern in PATTERNS.items():
        if re.search(pattern, decoded, re.I):
            raise HoneypotTrapTriggered(attack, "")
    if CONTROL.search(raw) or CONTROL.search(decoded) or "\\" in raw or re.search(r"\s", raw):
        raise HoneypotTrapTriggered("unsafe URL characters", "")

    cleaned = raw.replace("[.]", ".")
    cleaned = re.sub(r"^hxxp(s?)://", r"http\1://", cleaned, flags=re.I)
    try:
        supplied_ip = ipaddress.ip_address(cleaned.strip("[]"))
    except ValueError:
        supplied_ip = None
    if isinstance(supplied_ip, ipaddress.IPv6Address):
        cleaned = f"[{supplied_ip}]"
    candidate = cleaned if "://" in cleaned else "https://" + cleaned
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid URL or port.") from None
    if parsed.scheme not in {"http", "https"}:
        raise HoneypotTrapTriggered("forbidden URL scheme", "")
    if parsed.username is not None or parsed.password is not None or "%" in parsed.netloc:
        raise HoneypotTrapTriggered("ambiguous URL authority", "")
    hostname = (parsed.hostname or "").rstrip(".").lower()
    if not hostname:
        raise ValueError("A hostname is required.")

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None
    if ip is not None:
        if is_ip_unsafe(str(ip)):
            raise HoneypotTrapTriggered("non-public IP address", "")
        domain = str(ip)
    else:
        try:
            domain = idna.encode(hostname, uts46=True, std3_rules=True).decode("ascii").rstrip(".")
        except idna.IDNAError:
            raise ValueError("Invalid hostname.") from None
        if (
            "." not in domain
            or domain.endswith(BLOCKED_SUFFIXES)
            or domain in {"localhost.localdomain", "metadata.google.internal"}
            or AMBIGUOUS_IP.fullmatch(domain)
        ):
            raise HoneypotTrapTriggered("local or ambiguous hostname", "")

    answers = [str(ip)] if ip is not None else []
    if resolve and not answers:
        try:
            answers = sorted({a[4][0] for a in socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)})
        except OSError:
            pass
        if any(is_ip_unsafe(answer) for answer in answers):
            raise HoneypotTrapTriggered("non-public DNS result", "")

    authority = f"[{domain}]" if isinstance(ip, ipaddress.IPv6Address) else domain
    if port is not None and (parsed.scheme, port) not in {("https", 443), ("http", 80)}:
        authority += f":{port}"
    return {
        "original_input": raw,
        "url": urlunsplit((parsed.scheme, authority, parsed.path or "/", parsed.query, "")),
        "domain": domain,
        "path": parsed.path or "/",
        "query": parsed.query,
        "resolved_ip": answers[0] if answers else None,
        "ssrf_blocked": False,
        "prompt_injection_attempted": False,
    }


def defang_ioc(url: str, domain: str, ip: str | None = None) -> dict:
    return {
        "defanged_url": url.replace("https://", "hxxps://", 1).replace("http://", "hxxp://", 1).replace(".", "[.]"),
        "defanged_domain": domain.replace(".", "[.]"),
        "defanged_ip": ip.replace(".", "[.]") if ip else "N/A",
    }


def printable(text: str, limit: int = 300) -> str:
    return CONTROL.sub(" ", str(text))[:limit]
