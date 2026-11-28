"""Versioned evidence rules and conservative verdict calculation."""

from dataclasses import asdict, dataclass

VERSION = "7.8.1"
RULES = {
    "NRD_24H": ("New domain · under 24 hours", "registration", 40, "T1583.001"),
    "NRD_30D": ("New domain · up to 30 days", "registration", 35, "T1583.001"),
    "BRAND_CONFUSABLE": ("Visually confusable brand domain", "lexical", 28, "T1566.002"),
    "BRAND_LOOKALIKE": ("Brand lookalike domain", "lexical", 22, "T1566.002"),
    "BRAND_LURE": ("Brand name with a credential lure", "lexical", 20, "T1566.002"),
    "PUNYCODE_LABEL": ("Internationalized domain label", "lexical", 0, None),
    "RISKY_SUFFIX": ("Frequently abused domain suffix", "lexical", 8, None),
    "HOSTED_TENANT": ("Shared hosting tenant", "lexical", 0, None),
    "URL_BRAND_SUBDOMAIN": ("Brand name in an unrelated subdomain", "lexical", 28, "T1566.002"),
    "URL_IP_LOGIN": ("Numeric address with a sign-in path", "lexical", 25, "T1566.002"),
    "URL_OFFSITE_REDIRECT": ("Sign-in URL carries an off-site redirect destination", "lexical", 8, None),
    "URL_SHARED_TENANT_LURE": ("Shared-hosting tenant name combines a brand and sign-in lure", "lexical", 26, "T1566.002"),
    "TI_HASH_LISTED": ("Exact hash listed in MalShare", "file_reputation", 35, None),
    "TI_URL_EXACT": ("Current exact URL reputation match", "url_reputation", 75, "T1566.002"),
    "TI_URLSCAN_RECENT": ("Recent malicious scan of the exact URL", "url_reputation", 40, "T1566.002"),
    "TI_HISTORICAL_URL": ("Historical dataset URL match", "historical", 30, None),
    "TI_HISTORICAL_BENIGN": ("Exact URL labeled benign in the historical dataset", "historical", 0, None),
    "TI_HISTORICAL_CONFLICT": ("Exact URL has conflicting historical labels", "historical", 0, None),
    "TI_HISTORICAL_FRAGMENT": ("Historical match for the URL without its fragment", "historical", 0, None),
    "TI_DOMAIN": ("Domain reputation match", "domain_reputation", 35, None),
    "TI_IP": ("IP reputation match", "infrastructure", 12, None),
    "HTML_CROSS_ORIGIN_FORM": ("Credential form posts to a different domain", "artifact", 45, "T1056"),
    "HTML_CLIPBOARD_CONTEXT": ("Clipboard and command guidance present", "artifact", 0, None),
    "HTML_SUBMIT_OVERRIDE": ("Submit control changes credential destination", "artifact", 45, "T1056"),
    "HTML_CLIPBOARD_EXEC": ("Verification prompt copies a shell command", "artifact", 55, "T1204.004"),
    "HTML_LINK_MISMATCH": ("Displayed domain differs from link destination", "artifact", 28, "T1566.002"),
    "HTML_WEBHOOK_FORM": ("Credential form posts to a messaging endpoint", "artifact", 55, "T1056"),
    "HTML_INSECURE_PASSWORD": ("Password submitted over HTTP", "artifact", 25, None),
    "HTML_CREDENTIAL_FORM_REDIRECT": ("HTML base changes a credential form destination", "artifact", 45, "T1056"),
    "HTML_PASSWORD_QUERY": ("Password form explicitly uses GET", "artifact", 18, None),
    "HTML_PASSWORD_MAILTO": ("Credential form targets an email client", "artifact", 35, "T1056"),
    "HTML_OTP_CROSS_ORIGIN": ("One-time code form posts to a different site", "artifact", 30, "T1056"),
    "HTML_EXTERNAL_REFRESH": ("Rapid refresh routes to another site", "artifact", 0, None),
    "EMAIL_DOUBLE_EXTENSION": ("Attachment has a misleading double extension", "attachment", 34, "T1036.007"),
    "EMAIL_ACTIVE_ATTACHMENT": ("Attachment name has an executable or script extension", "attachment", 25, "T1566.001"),
    "EMAIL_ARCHIVE_LURE": ("Archive attachment accompanies an urgent document subject", "attachment", 12, None),
    "EMAIL_BIDI_FILENAME": ("Attachment name contains bidirectional override characters", "attachment", 28, "T1036"),
    "EMAIL_REPLY_TO": ("Reply-To uses a different domain", "email", 0, None),
    "EMAIL_REPLY_TO_CORROBORATED": ("External Reply-To accompanies deceptive or listed links", "email", 12, None),
    "EMAIL_ARCHIVED_THREAT": ("Email link matches an archived threat URL", "email", 30, "T1566.002"),
    "EMAIL_LINK_IMPERSONATION": ("Email link points to a lookalike or deceptive brand host", "email", 28, "T1566.002"),
    "EMAIL_ATTACHED_MESSAGE": ("Separate email attached to the message", "email", 0, None),
    "EMAIL_CREDENTIAL_DEADLINE": ("Urgent credential or account deadline", "email", 20, "T1566"),
    "EMAIL_CREDENTIAL_REPLY": ("Message asks the recipient to send a password or one-time code", "email", 35, "T1566"),
    "EMAIL_ENVELOPE": ("From differs from envelope domain", "email", 0, None),
    "EMAIL_LINK_MISMATCH": ("Email link label differs from destination", "email", 28, "T1566.002"),
    "EMAIL_AUTH_CLAIM": ("Authentication-Results contains a failure claim", "email", 0, None),
}
CAPS = {"file_reputation": 35, "historical": 30, "lexical": 30, "registration": 40, "domain_reputation": 40, "infrastructure": 15, "email": 48, "artifact": 75, "attachment": 34, "url_reputation": 75}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    label: str
    category: str
    points: int
    source: str
    detail: str
    mitre: str | None


def finding(rule_id: str, source: str, detail: str) -> Finding:
    label, category, points, mitre = RULES[rule_id]
    return Finding(rule_id, label, category, points, source, detail, mitre)


def catalogue() -> list[dict]:
    return [asdict(finding(rule_id, "", "")) for rule_id in RULES]


def assess(findings: list[Finding], *, coverage_sufficient: bool, trusted_root: bool = False) -> dict:
    observed: dict[tuple[str, str], Finding] = {}
    for match in findings:
        observed.setdefault((match.rule_id, match.source), match)
    evidence = sorted(observed.values(), key=lambda item: -item.points)
    # Different providers may share the same upstream intelligence.
    # Score each rule once and cap related signals.
    totals: dict[str, int] = {}
    rule_ids = {item.rule_id for item in evidence}
    for rule_id in sorted(rule_ids):
        _, category, points, _ = RULES[rule_id]
        totals[category] = min(CAPS[category], totals.get(category, 0) + points)
    totals = {category: points for category, points in totals.items() if points}
    strong = bool(rule_ids & {"TI_URL_EXACT"})
    contributed = sum(totals.values())
    score = min(100 if strong else 69, contributed)
    verdict = (
        "MALICIOUS" if score >= 70 else
        "SUSPICIOUS" if score >= 25 else
        "INCONCLUSIVE" if not coverage_sufficient and not (trusted_root and score == 0) else
        "LOW_SIGNAL" if score else
        "TRUSTED_ROOT" if trusted_root else "CLEAN"
    )
    return {
        "risk_score": score,
        "verdict": verdict,
        "triggers": [f"{item.label} · {item.detail}" for item in evidence if item.points],
        "mitre_techniques": [{"id": technique} for technique in sorted({item.mitre for item in evidence if item.mitre})],
        "evidence": [asdict(item) for item in evidence],
        "contributions": totals,
        "uncapped_total": sum(item.points for item in evidence),
        "score_capped": score < sum(item.points for item in evidence),
    }
