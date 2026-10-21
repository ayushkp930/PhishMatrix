import ssl
import socket
import asyncio
from datetime import datetime, timezone
import httpx
import dns.resolver

def raw_socket_whois(domain: str) -> dict:
    parts = domain.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    tld = parts[-1].lower() if len(parts) > 1 else "com"
    server = {"com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com", "in": "whois.registry.in"}.get(tld, f"whois.nic.{tld}")
    try:
        with socket.create_connection((server, 43), timeout=2.0) as s:
            s.sendall(f"{root}\r\n".encode())
            res = b""
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                res += chunk
        text = res.decode("utf-8", errors="ignore")
        reg, created, expiry, abuse = "Standard Registrar", None, None, None
        for line in text.splitlines():
            low = line.lower().strip()
            if "registrar:" in low and reg == "Standard Registrar": reg = line.split(":", 1)[1].strip()
            elif any(k in low for k in ["creation date:", "created on:"]) and not created: created = line.split(":", 1)[1].strip()[:10]
            elif any(k in low for k in ["registry expiry date:", "expiration date:"]) and not expiry: expiry = line.split(":", 1)[1].strip()[:10]
            elif "abuse" in low and "email:" in low and not abuse: abuse = line.split(":", 1)[1].strip()
        return {"registrar": reg, "creation_date": created, "expiry_date": expiry, "abuse_email": abuse}
    except Exception:
        return {}

async def lookup_whois_rdap(client: httpx.AsyncClient, domain: str) -> dict:
    parts = domain.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    reg, created, expiry, abuse, ns = "Privacy Protected", None, None, "abuse@registry.net", []
    try:
        resp = await client.get(f"https://rdap.org/domain/{root}", follow_redirects=True, timeout=3.0)
        if resp.status_code == 200:
            data = resp.json()
            for n in data.get("nameservers", []):
                if n.get("ldhName"): ns.append(n["ldhName"].lower())
            for ev in data.get("events", []):
                if ev.get("eventAction") == "registration": created = ev.get("eventDate", "")[:10]
                elif ev.get("eventAction") == "expiration": expiry = ev.get("eventDate", "")[:10]
    except Exception:
        pass

    if not created:
        raw = raw_socket_whois(root)
        if raw.get("registrar"): reg = raw["registrar"]
        created = raw.get("creation_date")
        expiry = raw.get("expiry_date") or expiry
        abuse = raw.get("abuse_email") or abuse

    age_days, is_nrd = None, False
    if created:
        try:
            dt = datetime.strptime(created[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            age_days = max(0, (datetime.now(timezone.utc) - dt).days)
            if age_days <= 30: is_nrd = True
        except Exception:
            pass

    return {
        "queried_domain": root, "registrar": reg, "creation_date": created or "Established",
        "expiry_date": expiry or "Active", "domain_age_days": age_days,
        "is_newly_registered": is_nrd, "abuse_contact": abuse, "nameservers": ns[:4]
    }

def inspect_ssl_certificate(domain: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=2.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                org = issuer.get("organizationName", issuer.get("commonName", "CA"))
                return {
                    "ssl_enabled": True, "issuer": org, "subject_cn": subject.get("commonName", domain),
                    "valid_from": cert.get("notBefore", ""), "valid_until": cert.get("notAfter", ""),
                    "is_free_short_lived_cert": any(k in org.lower() for k in ["let's encrypt", "zerossl", "cloudflare"]),
                    "protocol_version": ssock.version()
                }
    except Exception:
        return {"ssl_enabled": False, "issuer": "HTTP Only / Unreachable", "subject_cn": domain}

def inspect_dns_records(domain: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.5; resolver.lifetime = 1.5
    def q(typ):
        try: return [r.to_text().strip('"') for r in resolver.resolve(domain, typ)]
        except Exception: return []
    txt = q("TXT")
    dmarc = []
    try: dmarc = [r.to_text().strip('"') for r in resolver.resolve(f"_dmarc.{domain}", "TXT")]
    except Exception: pass
    spf = any("v=spf1" in t.lower() for t in txt)
    dm = any("v=dmarc1" in t.lower() for t in dmarc)
    return {"a_records": q("A")[:4], "mx_records": q("MX")[:3], "spf_configured": spf, "dmarc_configured": dm}

async def unroll_redirects_and_fetch(client: httpx.AsyncClient, url: str, ssrf_blocked: bool) -> dict:
    if ssrf_blocked: return {"redirect_chain": [url], "final_url": url, "html": "", "hop_count": 0}
    try:
        resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"}, follow_redirects=True, timeout=3.5)
        chain = [str(r.url) for r in resp.history] + [str(resp.url)]
        return {"redirect_chain": chain, "hop_count": len(resp.history), "final_url": str(resp.url), "status_code": resp.status_code, "server_header": resp.headers.get("server", "Hidden"), "html": resp.text[:100000]}
    except Exception:
        return {"redirect_chain": [url], "hop_count": 0, "final_url": url, "html": "", "server_header": "Offline"}
