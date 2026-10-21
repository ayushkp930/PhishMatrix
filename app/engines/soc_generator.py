from datetime import datetime, timezone

def generate_blue_team_arsenal(domain: str, ip: str, url: str, verdict: str, triggers: list, whois: dict, dom: dict) -> dict:
    """Auto-generates YARA, Sigma, Suricata IDS, Splunk SPL, Sentinel KQL, UFW rules & Takedown Draft."""
    clean_name = "".join(c if c.isalnum() else "_" for c in domain)[:30]
    date_now = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    target_ip = ip or "0.0.0.0"

    # 1. YARA Rule
    yara_rule = f"""rule PhishMatrix_{clean_name} {{
    meta:
        description = "Detects phishing infrastructure and DOM signatures for {domain}"
        author = "PhishMatrix Autonomous SOC Engine (Ayush Kumar Patel)"
        date = "{date_now}"
        verdict = "{verdict}"
    strings:
        $domain = "{domain}" ascii wide nocase
        $form_act = "{dom.get('form_action', 'login')[:30]}" ascii wide
        $tg_exfil = "api.telegram.org/bot" ascii
        $clickfix = "navigator.clipboard.writeText" ascii nocase
    condition:
        $domain and any of ($form_act, $tg_exfil, $clickfix)
}}"""

    # 2. Sigma Rule (DNS / Web Proxy)
    sigma_rule = f"""title: Suspicious Outbound Connection to {domain}
status: experimental
description: Detects DNS query or HTTP request to flagged domain {domain} ({verdict})
author: PhishMatrix Threat Intel
date: {date_now}
logsource:
    category: dns
detection:
    selection:
        query|endswith: '{domain}'
    condition: selection
level: {'critical' if verdict == 'MALICIOUS' else 'medium'}"""

    # 3. Suricata IDS Rule
    suricata_rule = f'alert http any any -> any any (msg:"PHISHMATRIX [{verdict}] Outbound Phishing Request to {domain}"; flow:established,to_server; http.host; content:"{domain}"; nocase; classtype:social-engineering; sid:9004201; rev:1;)'

    # 4. Splunk SPL & Microsoft Sentinel KQL
    splunk_spl = f'index=proxy OR index=firewall OR index=dns (dest_host="{domain}" OR dest_ip="{target_ip}" OR url="*{domain}*") | stats count earliest(_time) as FirstSeen latest(_time) as LastSeen values(src_ip) as AffectedHosts by dest_host, dest_ip, action'
    sentinel_kql = f'CommonSecurityLog | where DestinationHostName endswith "{domain}" or DestinationIP == "{target_ip}" | summarize EventCount=count(), Victims=make_set(SourceIP) by DestinationHostName, DestinationIP, DeviceAction'

    # 5. Linux UFW & iptables Block Commands
    ufw_cmd = f"sudo ufw deny out to {target_ip} comment 'PhishMatrix Block {domain}' && echo '0.0.0.0 {domain}' | sudo tee -a /etc/hosts"

    # 6. Automated Registrar & ISP Takedown Notice
    abuse_contact = whois.get("abuse_contact", "abuse@registrar.com")
    evidence_bullets = "\n".join(f"  - {t}" for t in triggers[:6]) or "  - Suspicious brand impersonation and credential collection"
    takedown_email = f"""To: {abuse_contact}, cert-in@cert-in.org.in
Subject: [URGENT ABUSE REPORT] Phishing & Credential Harvesting on {domain} ({target_ip})

Dear Abuse & Trust/Safety Team ({whois.get('registrar', 'Domain Registrar')}),

We are reporting an active cybersecurity threat hosted on your network/registrar infrastructure that violates your Acceptable Use Policy.

[INCIDENT SUMMARY]
- Malicious URL: {url.replace('.', '[.]')}
- Domain Name: {domain}
- Resolved IPv4: {target_ip}
- Threat Classification: {verdict}
- Timestamp (UTC): {datetime.now(timezone.utc).isoformat()}

[FORENSIC EVIDENCE & INDICATORS]
{evidence_bullets}

We kindly request the immediate suspension of the domain '{domain}' and null-routing of the associated phishing kit to prevent ongoing financial and credential theft.

Sincerely,
PhishMatrix Threat Intelligence Operations"""

    return {
        "yara_rule": yara_rule,
        "sigma_rule": sigma_rule,
        "suricata_rule": suricata_rule,
        "splunk_spl": splunk_spl,
        "sentinel_kql": sentinel_kql,
        "ufw_command": ufw_cmd,
        "takedown_notice": takedown_email
    }
