"""Generate scoped hunting rules and export the evidence actually observed."""

import json
import re
from hashlib import sha256
from ipaddress import ip_address
from uuid import NAMESPACE_URL, uuid5

from app.scoring import VERSION

HASH_ALGORITHMS = {32: "md5", 40: "sha1", 64: "sha256"}


def sigma(title, description, logsource, fields, condition="selection", level="informational"):
    # JSON scalars and flow mappings are valid YAML and preserve literal field values.
    selection = "\n".join(f"      {key}: {json.dumps(value)}" for key, value in fields.items())
    identity = json.dumps([logsource, fields, condition], sort_keys=True)
    return (
        f"title: {json.dumps(title)}\nid: {uuid5(NAMESPACE_URL, identity)}\nstatus: experimental\n"
        f"description: {json.dumps(description)}\nlogsource: {json.dumps(logsource)}\n"
        f"detection:\n    selection:\n{selection}\n    condition: {condition}\n"
        f"falsepositives:\n    - Authorized testing or legitimate activity with the same indicator\nlevel: {level}\n"
    )


def generate_blue_team_arsenal(host: str) -> dict[str, str]:
    try:
        address = str(ip_address(host))
    except ValueError:
        address = None
    if address:
        if "%" in address:
            return {}
        return {
            "sigma_rule": sigma(f"Network connection to {address}", "Sysmon network connection, destination only.",
                                {"product": "windows", "category": "network_connection"}, {"DestinationIp": address}),
            "splunk_spl": f'index=* (src_ip="{address}" OR dest_ip="{address}") | stats count',
            "sentinel_kql": f'CommonSecurityLog | where SourceIP == "{address}" or DestinationIP == "{address}"',
        }
    if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
        return {}
    digest = int(sha256(host.encode("ascii")).hexdigest()[:8], 16)
    escaped_host = re.escape(host)
    # This expression accepts an optional DNS root dot only at a token boundary.
    domain_pattern = rf"(^|[^a-z0-9_.-]){escaped_host}\.?($|[^a-z0-9_.-])"
    return {
        "sigma_rule": sigma(f"DNS query for {host}", "Exact Windows DNS query. Requires Sysmon DNS telemetry or equivalent.",
                            {"product": "windows", "category": "dns_query"}, {"QueryName": [host, host + "."]}),
        "splunk_spl": (f'index=* (query="{host}" OR query="{host}." OR dns_query="{host}" OR dns_query="{host}.") '
                       '| eval domain=coalesce(query,dns_query) | stats count min(_time) as first_seen by domain'),
        "sentinel_kql": f'DnsEvents | where trim_end(@"\\.", Name) =~ "{host}" | summarize Hits=count() by ClientIP, Name',
        "elastic_kql": f'dns.question.name : ("{host}" or "{host}.")',
        "crowdstrike_cql": f'#event_simpleName=DnsRequest (DomainName="{host}" or DomainName="{host}.") | groupBy([ComputerName, DomainName])',
        "wazuh_rule": (
            f'<group name="phishmatrix,dns,">\n  <rule id="{100000 + digest % 20000}" level="3">\n'
            f'    <decoded_as>json</decoded_as>\n    <field name="dns.question.name" type="pcre2">(?i)^{escaped_host}\\.?$</field>\n'
            f'    <description>PhishMatrix DNS lookup for {host}</description>\n  </rule>\n</group>'
        ),
        "suricata_rule": (
            f'alert tls any any -> any any (msg:"PhishMatrix SNI match {host}"; '
            f'tls.sni; content:"{host}"; startswith; endswith; nocase; sid:{1000000 + digest % 1000000}; rev:1;)'
        ),
        "yara_rule": (
            f'rule PhishMatrix_Domain_{digest:08X} {{\n    meta:\n        description = "Exact hostname in text, including UTF-16LE"\n'
            f'    strings:\n        $domain = /{domain_pattern}/ ascii wide nocase\n    condition:\n        $domain\n}}\n'
        ),
    }


def case_exports(case_id, timestamp, result, kind, *, host=None, digest=None):
    rules = generate_blue_team_arsenal(host) if host else {}
    verdict = result["verdict"]
    operation = "phishmatrix-triage"
    rule_ids = sorted({item["rule_id"] for item in result["evidence"]})
    event = {
        "@timestamp": timestamp,
        "event": {"id": case_id, "kind": "alert" if verdict in {"MALICIOUS", "SUSPICIOUS"} else "event",
                  "category": ["threat"], "action": operation, "risk_score": result["risk_score"]},
        "observer": {"product": "PhishMatrix", "version": VERSION},
        "phishmatrix": {"verdict": verdict, "rule_ids": rule_ids, "artifact_type": kind},
    }
    if host:
        try:
            ip_address(host)
            event["related"] = {"ip": [host]}
        except ValueError:
            event["related"] = {"hosts": [host]}
    if digest is not None:
        algorithm = HASH_ALGORITHMS[len(digest)]
        if not re.fullmatch("[0-9a-f]+", digest):
            raise ValueError("Invalid digest")
        event["file"] = {"hash": {algorithm: digest}}
        rule = (
            f'import "hash"\n\nrule PhishMatrix_{algorithm}_{digest} {{\n'
            f'    condition:\n        hash.{algorithm}(0, filesize) == "{digest}"\n}}\n'
        )
        rules["yara_hash"] = rule
        if kind == "hash":
            rules["sigma_process_hash"] = sigma(
                f"Process image hash {digest}", "Windows process creation with configured image hashing.",
                {"product": "windows", "category": "process_creation"}, {"Hashes|contains": f"{algorithm.upper()}={digest}"},
            )
    scored = sorted({item["rule_id"] for item in result["evidence"] if item["points"]})
    if scored:
        rules["sigma_case"] = sigma(
            f"PhishMatrix {kind} triage with {len(scored)} scored finding(s)",
            "Matches exported PhishMatrix events with all listed findings. Ingest case events with their structured fields.",
            {"product": "phishmatrix"}, {"observer.product": "PhishMatrix", "event.action": operation,
            "phishmatrix.artifact_type": kind,
            **({"phishmatrix.rule_ids": scored[0]} if len(scored) == 1 else {"phishmatrix.rule_ids|all": scored})}, level="low",
        )
    return {"soc_arsenal": rules, "siem_event": event}
