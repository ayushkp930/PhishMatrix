import asyncio
import pytest
from app.security import normalize_target, defang_ioc, sanitize_for_llm, HoneypotTrapTriggered
from app.whitelist import is_whitelisted_domain, WHITELIST_1000_DOMAINS
from app.engines.heuristics import run_heuristic_analysis
from app.orchestrator import investigate_target

def test_1000_whitelist_engine():
    assert len(WHITELIST_1000_DOMAINS) >= 1000
    assert is_whitelisted_domain("github.com", "https://github.com") is True
    assert is_whitelisted_domain("onlinesbi.sbi", "https://onlinesbi.sbi") is True
    assert is_whitelisted_domain("sbi-kyc-update-pan.top", "https://sbi-kyc-update-pan.top") is False

    # Whitelisted domain should use 0 API credits
    res = asyncio.run(investigate_target("github.com"))
    assert res["summary"]["verdict"] == "CLEAN"
    assert res["scan_metadata"]["whitelist_fast_path"] is True
    assert res["scan_metadata"]["api_credits_used"] == 0

def test_honeypot_trap_xss_sqli_ssrf_prompt():
    # XSS triggers Honeypot
    with pytest.raises(HoneypotTrapTriggered) as exc:
        normalize_target("https://evil.com/<script>alert(1)</script>")
    assert "LOL 😂" in exc.value.message

    # SSRF triggers Honeypot
    with pytest.raises(HoneypotTrapTriggered) as exc2:
        normalize_target("http://127.0.0.1/admin")
    assert "LOL 😂" in exc2.value.message

    # Cloud Metadata SSRF triggers Honeypot
    with pytest.raises(HoneypotTrapTriggered):
        normalize_target("http://169.254.169.254/latest/meta-data/")

    # SQLi triggers Honeypot
    with pytest.raises(HoneypotTrapTriggered):
        normalize_target("https://evil.com/login?user=admin' OR 1=1--")

def test_full_orchestrator_and_12_defensive_rules():
    result = asyncio.run(investigate_target("sbi-kyc-update-pan.top"))
    assert result["summary"]["verdict"] == "MALICIOUS"
    arsenal = result["soc_arsenal"]
    assert "crowdstrike_cql" in arsenal
    assert "cloudflare_waf" in arsenal
    assert "modsecurity_rule" in arsenal
    assert "powershell_defender" in arsenal
