import asyncio
from app.security import normalize_target, defang_ioc
from app.engines.heuristics import run_heuristic_analysis
from app.email_parser import analyze_raw_email
from app.orchestrator import investigate_target

def test_defang_and_ssrf_guard():
    norm = normalize_target("https://paypal-login.top/auth")
    assert norm["domain"] == "paypal-login.top"
    defanged = defang_ioc(norm["url"], norm["domain"], "185.220.101.44")
    assert "hxxps://" in defanged["defanged_url"]
    assert "[.]" in defanged["defanged_domain"]

    loopback = normalize_target("http://127.0.0.1/admin")
    assert loopback["ssrf_blocked"] is True

def test_zero_day_heuristics_and_indian_scams():
    res = run_heuristic_analysis("https://sbi-kyc-update-pan.top/login", "sbi-kyc-update-pan.top", "/login", "")
    assert res["heuristic_score"] >= 50
    assert res["is_suspicious_tld"] is True
    assert res["indian_scam_type"] is not None

def test_email_spoofing_analyzer():
    raw = "From: a@sbi.co.in\nReturn-Path: b@evil.top\nAuthentication-Results: spf=fail; dmarc=fail\n\nVisit https://evil.top"
    parsed = analyze_raw_email(raw)
    assert parsed["header_spoof_mismatch"] is True
    assert parsed["email_risk_score"] >= 60

def test_full_orchestrator_zero_error():
    result = asyncio.run(investigate_target("sbi-kyc-update-pan.top"))
    assert result["summary"]["verdict"] == "MALICIOUS"
    assert result["dom_forensics"]["telegram_exfil"] is not None
    assert "yara_rule" in result["soc_arsenal"]
