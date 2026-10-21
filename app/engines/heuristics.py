import math
import re
from collections import Counter

PROTECTED_BRANDS = {
    "paypal": "PayPal Financial", "microsoft": "Microsoft / Office365", "google": "Google Workspace",
    "apple": "Apple iCloud", "amazon": "Amazon Retail/AWS", "netflix": "Netflix", "facebook": "Meta",
    "instagram": "Instagram", "whatsapp": "WhatsApp", "linkedin": "LinkedIn", "binance": "Binance",
    "coinbase": "Coinbase", "metamask": "MetaMask", "onlinesbi": "State Bank of India (SBI)",
    "sbicard": "SBI Card", "hdfcbank": "HDFC Bank", "icicibank": "ICICI Bank", "axisbank": "Axis Bank",
    "paytm": "Paytm", "phonepe": "PhonePe", "parivahan": "Parivahan e-Challan", "indiapost": "IndiaPost"
}

OFFICIAL_DOMAINS = {
    "paypal.com", "microsoft.com", "live.com", "office.com", "google.com", "apple.com", "icloud.com",
    "amazon.com", "amazon.in", "netflix.com", "facebook.com", "instagram.com", "whatsapp.com",
    "linkedin.com", "binance.com", "coinbase.com", "metamask.io", "onlinesbi.sbi", "sbi.co.in",
    "hdfcbank.com", "icicibank.com", "axisbank.com", "paytm.com", "phonepe.com", "parivahan.gov.in",
    "indiapost.gov.in", "github.com"
}

HIGH_RISK_TLDS = {".top", ".xyz", ".buzz", ".icu", ".tk", ".ml", ".ga", ".cf", ".gq", ".vip", ".work", ".click", ".link", ".zip", ".mov"}

ABUSED_CLOUD_HOSTS = {
    "pages.dev": "Cloudflare Pages", "workers.dev": "Cloudflare Workers", "web.app": "Google Firebase",
    "vercel.app": "Vercel", "netlify.app": "Netlify", "ngrok-free.app": "Ngrok Tunnel", "github.io": "GitHub Pages"
}

INDIAN_SCAM_PATTERNS = [
    (r"(sbi|hdfc|icici|axis|pnb).*(kyc|pan|update|verify|block|reward)", "Indian Banking KYC / Reward Scam"),
    (r"(echallan|parivahan|mparivahan)", "Fake Parivahan Traffic e-Challan Scam"),
    (r"(indiapost|delhivery|bluedart).*(address|track|customs|parcel)", "Fake Courier / IndiaPost Delivery Scam")
]

def calculate_shannon_entropy(text: str) -> float:
    if not text: return 0.0
    counts = Counter(text)
    length = len(text)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 2)

def run_heuristic_analysis(url: str, domain: str, path: str, query: str) -> dict:
    score, flags, mitre = 0, [], []
    full_target = f"{domain}{path}?{query}".lower()
    parts = domain.split(".")
    tld = f".{parts[-1]}" if len(parts) > 1 else ""
    sld = parts[-2] if len(parts) >= 2 else domain
    reg_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    is_official = reg_domain in OFFICIAL_DOMAINS

    if "xn--" in domain:
        score += 40
        flags.append("IDN Homograph Attack: Punycode ('xn--') domain detected")
        mitre.append({"id": "T1583.001", "name": "Acquire Infrastructure: Domains"})

    if tld in HIGH_RISK_TLDS and not is_official:
        score += 18
        flags.append(f"High-Risk TLD: Abused '{tld}' extension")

    abused_cloud = None
    for suffix, name in ABUSED_CLOUD_HOSTS.items():
        if domain.endswith(suffix) and domain != suffix:
            abused_cloud = name
            score += 15
            flags.append(f"Hosted on Free Cloud Subdomain: {name}")

    brand = None
    if not is_official:
        for b_key, b_label in PROTECTED_BRANDS.items():
            if b_key in domain or b_key in path.lower():
                brand = b_label
                score += 38
                flags.append(f"Brand Impersonation: Targets '{b_label}'")
                mitre.append({"id": "T1566.002", "name": "Spearphishing Link"})
                break

    scam_type = None
    if not is_official:
        for pat, label in INDIAN_SCAM_PATTERNS:
            if re.search(pat, full_target):
                scam_type = label
                score += 35
                flags.append(f"Indian Threat Signature: {label}")
                break

    lures = ["login", "verify", "secure", "account", "update", "banking", "signin", "kyc", "unlock"]
    matched_lures = [k for k in lures if k in full_target]
    if matched_lures and not is_official:
        score += min(len(matched_lures) * 8, 25)
        flags.append(f"Deceptive Lure Keywords: {', '.join(matched_lures[:3])}")

    if "@" in url:
        score += 35
        flags.append("URL Credential Obfuscation: '@' symbol redirection trick")

    entropy = calculate_shannon_entropy(sld)
    if entropy > 3.9 and len(sld) > 10 and not is_official:
        score += 15
        flags.append(f"High Domain Entropy ({entropy} bits): Randomized DGA URL")

    return {
        "heuristic_score": min(score, 95), "entropy": entropy, "tld": tld,
        "is_suspicious_tld": tld in HIGH_RISK_TLDS, "is_punycode": "xn--" in domain,
        "impersonated_brand": brand, "indian_scam_type": scam_type,
        "abused_cloud_provider": abused_cloud, "flags": flags, "mitre_techniques": mitre
    }
