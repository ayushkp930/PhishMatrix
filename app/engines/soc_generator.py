"""SOC hunting templates and structured events for validated indicators."""

import json
import re
from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import ip_address
from uuid import NAMESPACE_DNS, uuid5


from app.scoring import VERSION

def generate_blue_team_arsenal(host: str) -> dict[str, str]:
    try:
        ip_address(host)
        return {
            "splunk_spl": f'index=* (src_ip="{host}" OR dest_ip="{host}") | stats count by src_ip dest_ip',
            "sentinel_kql": f'CommonSecurityLog | where SourceIP == "{host}" or DestinationIP == "{host}"',
        }
    except ValueError:
        pass
    # Templates only accept hostnames that cannot introduce query syntax.
    if not re.fullmatch(r"[a-z0-9.-]{1,253}", host):
        return {}
    digest = int(sha256(host.encode("ascii")).hexdigest()[:8], 16)
    wazuh_id = 100000 + digest % 20000
    suricata_id = 1000000 + digest % 1000000
    escaped_host = re.escape(host)
    return {
        "sigma_rule": (
            f"title: DNS lookup for {host}\nid: {uuid5(NAMESPACE_DNS, host)}\nstatus: experimental\n"
            "description: Review DNS lookup matches for the investigated host.\n"
            "logsource:\n  category: dns\ndetection:\n"
            f"  selection:\n    query: {json.dumps(host)}\n  condition: selection\nlevel: medium\n"
        ),
        "splunk_spl": f'index=* (query="{host}" OR dns_query="{host}") | stats count min(_time) as first_seen by src query',
        "sentinel_kql": f'DnsEvents | where trim_end(@"\\.", Name) =~ "{host}" | summarize Hits=count() by ClientIP, Name',
        "elastic_kql": f'dns.question.name : "{host}"',
        "crowdstrike_cql": f'#event_simpleName=DnsRequest DomainName="{host}" | groupBy([ComputerName, DomainName])',
        "wazuh_rule": (
            f'<group name="phishmatrix,dns,">\n  <rule id="{wazuh_id}" level="7">\n'
            f'    <decoded_as>json</decoded_as>\n    <field name="dns.question.name" type="pcre2">(?i)^{escaped_host}\\.?$</field>\n'
            f'    <description>PhishMatrix DNS lookup for {host}</description>\n  </rule>\n</group>'
        ),
        "suricata_rule": (
            f'alert tls any any -> any any (msg:"PhishMatrix SNI match {host}"; '
            f'tls.sni; content:"{host}"; startswith; endswith; nocase; sid:{suricata_id}; rev:1;)'
        ),
        "yara_rule": (
            f'rule PhishMatrix_Domain_{digest:08X} {{\n    strings:\n        $domain = "{host}" ascii wide nocase\n'
            "    condition:\n        filesize < 5MB and $domain\n}\n"
        ),
    }


def siem_event(case_id: str, host: str, result: dict) -> dict:
    event = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "event": {
            "id": case_id,
            "kind": "alert" if result["verdict"] in {"MALICIOUS", "SUSPICIOUS"} else "event",
            "category": ["threat"],
            "action": "phishmatrix-triage",
            "risk_score": result["risk_score"],
        },
        "observer": {"product": "PhishMatrix", "version": VERSION},
        "phishmatrix": {
            "verdict": result["verdict"],
            "rule_ids": sorted({item["rule_id"] for item in result["evidence"]}),
        },
    }
    try:
        ip_address(host)
        event["related"] = {"ip": [host]}
    except ValueError:
        event["dns"] = {"question": {"name": host}}
    return event
