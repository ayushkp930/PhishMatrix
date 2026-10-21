import socket
import ipaddress
from urllib.parse import urlparse

def normalize_target(raw_input: str) -> dict:
    cleaned = raw_input.strip().replace("[.]", ".").replace("hxxps://", "https://").replace("hxxp://", "http://")
    url = cleaned if cleaned.startswith(("http://", "https://")) else "https://" + cleaned
    parsed = urlparse(url)
    domain = (parsed.netloc or parsed.path.split("/")[0]).split(":")[0].lower().strip()
    path = parsed.path or "/"
    query = parsed.query or ""

    resolved_ip = None
    is_private_or_loopback = False
    try:
        ip_obj = ipaddress.ip_address(domain)
        resolved_ip = str(ip_obj)
        is_private_or_loopback = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        try:
            resolved_ip = socket.gethostbyname(domain)
            ip_obj = ipaddress.ip_address(resolved_ip)
            is_private_or_loopback = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except Exception:
            resolved_ip = None

    return {
        "original_input": raw_input.strip(),
        "url": url,
        "domain": domain,
        "path": path,
        "query": query,
        "resolved_ip": resolved_ip,
        "ssrf_blocked": is_private_or_loopback
    }

def defang_ioc(url: str, domain: str, ip: str = None) -> dict:
    return {
        "defanged_url": url.replace("https://", "hxxps://").replace("http://", "hxxp://").replace(".", "[.]"),
        "defanged_domain": domain.replace(".", "[.]"),
        "defanged_ip": ip.replace(".", "[.]") if ip else "N/A"
    }
