from datetime import datetime, timezone

def generate_blue_team_arsenal(domain: str, ip: str, url: str, verdict: str, triggers: list, whois: dict, dom: dict) -> dict:
    clean_name = "".join(c if c.isalnum() else "_" for c in domain)[:30]
    date_now = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    target_ip = ip or "0.0.0.0"

    # 1. YARA Phishing Kit & DOM Signature
    yara_rule = f"""rule PhishMatrix_{clean_name} {{
    meta:
        description = "Detects phishing kit DOM and C2 exfiltration for {domain}"
        author = "PhishMatrix v5.0 Autonomous SOAR (Ayush Kumar Patel)"
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

    # 2. Sigma SIEM Detection Rule (DNS + Web Proxy)
    sigma_rule = f"""title: PhishMatrix Alert - Outbound Connection to {domain}
status: production
description: Detects DNS query or HTTP proxy request to investigated domain {domain} ({verdict})
author: PhishMatrix Threat Intel
date: {date_now}
logsource:
    category: dns
detection:
    selection:
        query|endswith:
            - '{domain}'
    condition: selection
level: {'critical' if verdict == 'MALICIOUS' else 'medium'}"""

    # 3. Suricata / Snort 3 IDS Rule
    suricata_rule = (
        f'alert http any any -> any any (msg:"PHISHMATRIX [{verdict}] Outbound HTTP Request to {domain}"; '
        f'flow:established,to_server; http.host; content:"{domain}"; nocase; classtype:social-engineering; sid:9005101; rev:1;)\n'
        f'alert tls any any -> any any (msg:"PHISHMATRIX [{verdict}] TLS SNI Match for {domain}"; '
        f'flow:established,to_server; tls.sni; content:"{domain}"; nocase; sid:9005102; rev:1;)'
    )

    # 4. Splunk SPL & Microsoft Sentinel KQL
    splunk_spl = f'index=proxy OR index=firewall OR index=dns (dest_host="*{domain}" OR dest_ip="{target_ip}" OR url="*{domain}*") | stats count earliest(_time) as FirstSeen latest(_time) as LastSeen values(src_ip) as CompromisedHosts values(user) as AffectedUsers by dest_host, dest_ip, action'
    sentinel_kql = f'DeviceNetworkEvents | where RemoteUrl has "{domain}" or RemoteIP == "{target_ip}" | summarize AlertCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), AffectedEndpoints=make_set(DeviceName) by InitiatingProcessAccountName, RemoteUrl, RemoteIP'

    # 5. CrowdStrike Falcon LogScale (CQL) & Elastic Kibana KQL
    crowdstrike_cql = f'#event_simpleName=/^(DnsRequest|NetworkConnectIP4)$/ | (DomainName=/.*{domain}/i OR RemoteAddressIP4="{target_ip}") | groupBy([aid, ComputerName, UserName, DomainName, RemoteAddressIP4])'
    elastic_kql = f'destination.domain : "*{domain}" or destination.ip : "{target_ip}" or url.domain : "{domain}"'

    # 6. Cloudflare WAF Expression & ModSecurity OWASP CRS Rule
    cloudflare_waf = f'(http.request.uri.query contains "{domain}" or http.referer contains "{domain}" or ip.src eq {target_ip})'
    modsecurity_rule = f'SecRule REQUEST_HEADERS:Host|ARGS|REQUEST_URI "@rx (?i){domain.replace(".", "\\.")}" "id:950401,phase:1,deny,status:403,log,msg:\'PhishMatrix WAF Block: {domain}\'"'

    # 7. Zeek (Bro) Network Threat Intelligence Script
    zeek_script = f"""event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {{
    if ( /{domain.replace('.', '\\.')}$/i in query ) {{
        NOTICE([$note=DNS::Suspicious_Domain, $conn=c, $msg=fmt("PhishMatrix Alert: DNS query to {domain} (%s)", c$id$orig_h)]);
    }}
}}"""

    # 8. Linux UFW / iptables + Windows PowerShell Defender Block
    ufw_cmd = (
        f"# Linux UFW & iptables Block + DNS Sinkhole:\n"
        f"sudo ufw deny out to {target_ip} comment 'PhishMatrix Block {domain}'\n"
        f"sudo iptables -A OUTPUT -d {target_ip} -j DROP\n"
        f"echo '0.0.0.0 {domain}' | sudo tee -a /etc/hosts"
    )
    powershell_defender = (
        f"# Windows Defender & Firewall Block (Run as Administrator):\n"
        f"New-NetFirewallRule -DisplayName 'PhishMatrix Block {domain}' -Direction Outbound -RemoteAddress {target_ip} -Action Block\n"
        f"Add-Content -Path $env:windir\\System32\\drivers\\etc\\hosts -Value \"`n0.0.0.0 {domain}\""
    )

    # 9. Automated Registrar & CERT-In Abuse Takedown Notice
    abuse_contact = whois.get("abuse_contact", "abuse@registrar.com")
    evidence_bullets = "\n".join(f"  - {t}" for t in triggers[:6]) or "  - Suspicious brand impersonation and credential collection"
    takedown_email = f"""To: {abuse_contact}, incident@cert-in.org.in
Subject: [URGENT ABUSE REPORT] Phishing & Malicious Infrastructure on {domain} ({target_ip})

Dear Abuse & Trust/Safety Team ({whois.get('registrar', 'Domain Registrar')}),

We are reporting an active cybersecurity threat hosted on your infrastructure that violates your Acceptable Use Policy.

[INCIDENT SUMMARY]
- Malicious URL: {url.replace('.', '[.]')}
- Domain Name: {domain}
- Resolved IPv4: {target_ip}
- Threat Classification: {verdict}
- Timestamp (UTC): {datetime.now(timezone.utc).isoformat()}

[FORENSIC EVIDENCE & INDICATORS]
{evidence_bullets}

We request immediate suspension of the domain '{domain}' and null-routing of the associated phishing kit.

Sincerely,
PhishMatrix Autonomous SOAR Operations"""

    return {
        "yara_rule": yara_rule,
        "sigma_rule": sigma_rule,
        "suricata_rule": suricata_rule,
        "splunk_spl": splunk_spl,
        "sentinel_kql": sentinel_kql,
        "crowdstrike_cql": crowdstrike_cql,
        "elastic_kql": elastic_kql,
        "cloudflare_waf": cloudflare_waf,
        "modsecurity_rule": modsecurity_rule,
        "zeek_script": zeek_script,
        "ufw_command": ufw_cmd,
        "powershell_defender": powershell_defender,
        "takedown_notice": takedown_email
    }
