"""Email-only weights. Caps and effective contributions apply after correlation."""
from app.scoring import RULES
from app.email_unicode import INVISIBLE

# label, family, maximum weight, severity, analyst guidance
DEFINITIONS = {
    "EMAIL_CREDENTIAL_PORTAL": ("Credential entry requested with a deceptive destination", "email", 30, "HIGH", "Compare the destination with the published sign-in URL before entering credentials."),
    "BEC_PAYMENT_DIVERSION": ("Payment diversion with a suspect identity and pressure", "correlation", 18, "HIGH", "Independently verify all three signals against the purchase order, vendor master file and approval chain."),
    "BEC_BANK_DETAIL_CHANGE": ("Changed payment destination", "payment", 35, "HIGH", "A supplier may have changed banks. Call the vendor using the number already on file."),
    "BEC_EXECUTIVE_PRESSURE": ("Payment instruction with urgency or secrecy", "pressure", 28, "MEDIUM", "Check the deadline and transfer approval with the requester through a known channel."),
    "BEC_MISSING_MANDATE": ("Payment change cites a missing attachment", "mandate", 9, "LOW", "A gateway may have removed the file or a paste may omit it. Inspect the original message."),
    "EMAIL_ROLE_DOMAIN": ("Claimed identity uses an unexpected sender domain", "identity", 18, "MEDIUM", "A contractor or small business may use an external mailbox. Verify against the directory."),
    "EMAIL_CORPORATE_LURE": ("Sender domain uses a corporate-service naming pattern", "identity", 12, "LOW", "Legitimate service domains can use these words. Check ownership in vendor records."),
    "EMAIL_HOMOGRAPH": ("Visually confusable identity", "spoof", 45, "CRITICAL", "Compare the decoded label, codepoints and target with the organization's published name."),
    "EMAIL_TYPO_DOMAIN": ("Domain resembles a protected name", "spoof", 14, "MEDIUM", "Similar names can belong to unrelated companies. Confirm the registered domain."),
    "EMAIL_IDN": ("Internationalized hostname", "unicode_context", 0, "LOW", "IDNs are common. Verify the decoded spelling if unexpected."),
    "EMAIL_HIDDEN_KEYWORD": ("Invisible character interrupts a targeted keyword", "obfuscation", 8, "MEDIUM", "Copying formatted text can introduce invisible characters. Check the decoded original."),
    "EMAIL_CODE_SPOOF": ("Bank identifier contains a confusable character", "obfuscation", 15, "HIGH", "Verify the identifier against vendor master data before using it."),
    "EMAIL_URL_STRUCTURE": ("Link has a structural risk indicator", "link_structure", 18, "MEDIUM", "A sign-in path or short link may be routine. Verify the destination independently."),
    "EMAIL_ROUTE_RISK": ("External mail route with independent fraud evidence", "routing", 16, "HIGH", "Review service delegation, reply routing and gateway logs."),
    "EMAIL_AUTH_CORRELATED": ("Reported authentication failure accompanies deception", "auth", 10, "HIGH", "Confirm the failure in receiving-gateway logs. Forwarding may break authentication."),
}
CAPS = {"correlation": 18, "spoof": 45, "identity": 25, "routing": 16, "auth": 10, "email": 70, "artifact": 55,
        "attachment": 55, "payment": 35, "pressure": 28, "mandate": 9, "link_structure": 18,
        "unicode_context": 0, "obfuscation": 15}
NOTES = {
    "EMAIL_REPLY_TO": "A ticketing provider can receive replies. Confirm its delegation.",
    "EMAIL_ENVELOPE": "Return paths often belong to bounce processors. Verify the service and DKIM alignment.",
    "EMAIL_AUTH_CLAIM": "A pasted result is a claim. Consult your trusted receiver's logs.",
    "EMAIL_CREDENTIAL_DEADLINE": "Check whether your normal IT portal shows the same expiry.",
    "EMAIL_CREDENTIAL_REPLY": "Verify the request with your help desk using a known number.",
    "EMAIL_LINK_MISMATCH": "Marketing platforms can rewrite links. Verify the underlying destination.",
    "EMAIL_LINK_IMPERSONATION": "Verify the hostname against the brand's published domains.",
    "EMAIL_ARCHIVED_THREAT": "A historical label can be stale. Confirm current status independently.",
}
BOUNDS = ((80, "HIGH_CONFIDENCE_PHISHING"), (50, "LIKELY_PHISHING"), (20, "SUSPICIOUS"), (0, "LOW_RISK"))


def email_catalogue():
    return [dict(rule_id=key, label=label, category=family, points=weight, severity=severity,
                 false_positive_note=note) for key, (label, family, weight, severity, note) in DEFINITIONS.items()]


class EmailEvidence:
    def __init__(self):
        self.rows = {}

    def add(self, key, source, snippet, *, weight=None, detail=None, **extra):
        if key in DEFINITIONS:
            label, family, base, severity, note = DEFINITIONS[key]
            mitre = None
        else:
            label, family, base, mitre = RULES[key]
            severity = "HIGH" if base >= 25 or key in {"EMAIL_ENVELOPE", "EMAIL_REPLY_TO"} else "MEDIUM" if base else "LOW"
            note = NOTES.get(key, "Verify the original MIME part and its business purpose with the sender through a known channel.")
        weight = base if weight is None else weight
        if key in self.rows and self.rows[key]["points"] >= weight:
            return
        self.rows[key] = dict(rule_id=key, label=label, category=family, severity=severity, source=source,
                              matched_evidence=snippet[:320], false_positive_note=note, points=weight,
                              detail=detail or label, mitre=mitre, **extra)

    def result(self):
        rows = sorted(self.rows.values(), key=lambda r: (-r["points"], r["rule_id"]))
        totals = {}
        score = 0
        for row in rows:
            family = row["category"]
            room = CAPS[family] - totals.get(family, 0)
            points = min(row["points"], room, 100 - score)
            row["score_contribution"] = points
            if points:
                totals[family] = totals.get(family, 0) + points
            score += points
        raw = sum(r["points"] for r in rows)
        return dict(risk_score=score, email_risk_score=score, verdict=next(v for n, v in BOUNDS if score >= n),
                    evidence=rows, contributions=totals, uncapped_total=raw, score_capped=score < raw,
                    triggers=[r["label"] for r in rows if r["score_contribution"]],
                    mitre_techniques=[{"id": t} for t in sorted({r["mitre"] for r in rows if r["mitre"]})])


def visible_snippet(text):
    return "".join(f"[U+{ord(c):04X}]" if c in INVISIBLE or ord(c) < 32 and c not in "\n\r\t" else c for c in text)
