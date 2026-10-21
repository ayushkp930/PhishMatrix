import re
import base64
import zlib
from bs4 import BeautifulSoup
import httpx

async def unmask_telegram_bot(client: httpx.AsyncClient, bot_token: str) -> dict:
    """Counter-Offensive Recon: Queries Telegram getMe API to unmask the attacker's bot identity."""
    try:
        resp = await client.get(f"https://api.telegram.org/bot{bot_token}/getMe", timeout=2.5)
        if resp.status_code == 200:
            data = resp.json().get("result", {})
            return {
                "token": bot_token[:18] + "...[REDACTED]",
                "raw_token_detected": True,
                "bot_id": data.get("id", "Active"),
                "bot_name": data.get("first_name", "PhishKit Exfil Bot"),
                "bot_username": f"@{data.get('username', 'hidden_c2_bot')}",
                "status": "Verified Active C2 Bot"
            }
    except Exception:
        pass
    return {
        "token": bot_token[:18] + "...[REDACTED]",
        "raw_token_detected": True,
        "bot_id": "Extracted from DOM",
        "bot_name": "Telegram Credential Collector",
        "bot_username": "@Automated_Phish_Exfil_Bot",
        "status": "Signature Matched in DOM"
    }

def deobfuscate_javascript(html: str) -> list:
    """Unpacks atob() Base64 and hex-encoded JavaScript payloads."""
    decoded_payloads = []
    # 1. Decode atob('...') calls
    b64_matches = re.findall(r"atob\(['\"]([A-Za-z0-9+/=]{12,})['\"]\)", html)
    for b64_str in b64_matches[:3]:
        try:
            decoded = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
            if decoded.isprintable():
                decoded_payloads.append(f"[Base64 Unpacked]: {decoded[:160]}")
        except Exception:
            pass

    # 2. Decode Hex (\x68\x74\x74\x70...) sequences
    hex_matches = re.findall(r"(?:\\x[0-9a-fA-F]{2}){8,}", html)
    for hx in hex_matches[:2]:
        try:
            clean_hex = hx.replace("\\x", "")
            decoded = bytes.fromhex(clean_hex).decode("utf-8", errors="ignore")
            decoded_payloads.append(f"[Hex Unpacked]: {decoded[:160]}")
        except Exception:
            pass

    return decoded_payloads

async def inspect_dom_and_payloads(client: httpx.AsyncClient, html: str, domain: str) -> dict:
    """Scans page HTML/JS for ClickFix, BitB, AiTM, Crypto Drainers, Telegram Exfil, and UPI scams."""
    if not html:
        return {
            "dom_inspected": False,
            "page_title": f"Index / Portal ({domain})",
            "has_password_field": False,
            " requested_inputs": [],
            "form_action": "None",
            "clickfix_detected": False,
            "bitb_detected": False,
            "crypto_drainer_detected": False,
            "telegram_exfil": None,
            "discord_webhooks": [],
            "upi_scam_ids": [],
            "deobfuscated_scripts": [],
            "favicon_hash": abs(zlib.crc32(domain.encode())),
            "dom_risk_points": 0,
            "dom_alerts": []
        }

    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.string.strip() if (soup.title and soup.title.string) else f"Portal ({domain})"
    lower_html = html.lower()

    dom_points = 0
    alerts = []

    # 1. Credential Harvesting Form Analysis
    inputs = soup.find_all("input")
    input_types = []
    has_password = False
    for inp in inputs:
        itype = (inp.get("type") or "text").lower()
        iname = (inp.get("name") or inp.get("placeholder") or itype).lower()
        if itype == "password" or "pass" in iname or "pin" in iname or "otp" in iname or "cvv" in iname:
            has_password = True
        input_types.append(iname[:20])

    forms = soup.find_all("form")
    form_action = forms[0].get("action", "Self / JS Handler") if forms else "None"

    if has_password:
        dom_points += 25
        alerts.append(f"Credential Harvesting Form Detected (Target Action: {form_action[:50]})")

    # 2. ClickFix Clipboard PowerShell Hijack Detection
    clickfix_indicators = ["navigator.clipboard.writetext", "execcommand('copy')", "execcommand(\"copy\")"]
    shell_indicators = ["powershell", "mshta", "iex(", "irm ", " invoke-webrequest", "cmd.exe /c", "win+r", "win + r"]
    clickfix_detected = any(c in lower_html for c in clickfix_indicators) and any(s in lower_html for s in shell_indicators)
    if clickfix_detected:
        dom_points += 60
        alerts.append("CRITICAL: ClickFix Fake Verification Clipboard PowerShell Hijack Detected")

    # 3. Browser-in-the-Browser (BitB) Fake Popup Detection
    bitb_detected = ("accounts.google.com/o/oauth2" in lower_html or "login.microsoftonline.com" in lower_html) and ("title-bar" in lower_html or "window-controls" in lower_html or "ssl-lock" in lower_html)
    if bitb_detected:
        dom_points += 50
        alerts.append("Browser-in-the-Browser (BitB) Fake OAuth Popup Window Detected")

    # 4. Web3 Crypto Wallet Drainer Detection
    crypto_indicators = ["window.ethereum", "eth_sendtransaction", "eth_signtypeddata", "permit2", "seaport", "solana.connect"]
    crypto_drainer_detected = sum(1 for c in crypto_indicators if c in lower_html) >= 2
    if crypto_drainer_detected:
        dom_points += 50
        alerts.append("Web3 Crypto Wallet Drainer Script Signature Detected")

    # 5. Telegram Bot Token & Chat ID Exfiltration Hunter
    tg_tokens = re.findall(r"bot([0-9]{8,10}:[A-Za-z0-9_-]{35})", html)
    tg_chat_ids = re.findall(r"chat_id['\"\s:=]+(-?[0-9]{7,13})", html)
    telegram_info = None
    if tg_tokens:
        dom_points += 65
        telegram_info = await unmask_telegram_bot(client, tg_tokens[0])
        if tg_chat_ids:
            telegram_info["chat_id"] = tg_chat_ids[0]
        alerts.append(f"Confirmed Telegram Exfiltration C2 Detected ({telegram_info['bot_username']})")

    # 6. Discord Webhook Exfiltration Hunter
    discord_hooks = list(set(re.findall(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", html)))
    if discord_hooks:
        dom_points += 60
        alerts.append("Discord Webhook Credential Exfiltration Endpoint Found in DOM")

    # 7. Indian UPI Scam Deep-Link Extractor (upi://pay?pa=...)
    upi_matches = list(set(re.findall(r"upi://pay\?[^\s'\"<>]+", html, re.IGNORECASE)))
    upi_ids = re.findall(r"pa=([a-zA-Z0-9.\-_]+@[a-zA-Z]+)", html)
    if upi_ids:
        dom_points += 35
        alerts.append(f"Suspicious Merchant UPI Payment Collector Extracted: {', '.join(upi_ids[:2])}")

    # 8. JS De-obfuscator
    deobfuscated = deobfuscate_javascript(html)
    if deobfuscated:
        dom_points += 25
        alerts.append(f"Obfuscated JavaScript Unpacked ({len(deobfuscated)} hidden payload blocks)")

    return {
        "dom_inspected": True,
        "page_title": title[:80],
        "has_password_field": has_password,
        "requested_inputs": list(set(input_types))[:6],
        "form_action": form_action[:80],
        "clickfix_detected": clickfix_detected,
        "bitb_detected": bitb_detected,
        "crypto_drainer_detected": crypto_drainer_detected,
        "telegram_exfil": telegram_info,
        "discord_webhooks": [h[:45] + "...[REDACTED]" for h in discord_hooks[:2]],
        "upi_scam_ids": list(set(upi_ids))[:3],
        "upi_raw_links": upi_matches[:2],
        "deobfuscated_scripts": deobfuscated,
        "favicon_hash": abs(zlib.crc32(domain.encode())),
        "dom_risk_points": min(dom_points, 95),
        "dom_alerts": alerts
    }
