"""Report precision and recall for a small, synthetic, network-free triage fixture set."""

import json

from app.email_parser import analyze_raw_email
from app.engines.dom_hunter import inspect_html
from app.engines.heuristics import lexical_findings
from app.scoring import assess, finding


def url_result(host: str, rule: str | None = None, age_confirmed: bool = True) -> dict:
    evidence = lexical_findings(host, "/verify" if "update" in host else "/", "")
    if rule:
        evidence.append(finding(rule, "Synthetic fixture", "Injected benchmark evidence"))
    return assess(evidence, coverage_sufficient=age_confirmed)


def page_result(html: str) -> dict:
    _, evidence = inspect_html(html, "https://workbench.example/login")
    return assess(evidence, coverage_sufficient=False)


def main() -> int:
    cases = [
        ("Established official domain", False, url_result("github.com")),
        ("Internationalized unrelated domain", False, url_result("xn--bcher-kva.de")),
        ("Shared hosting page", False, url_result("docs.github.io")),
        ("New legitimate project domain", False, url_result("new-project.example", "NRD_24H")),
        ("Day-zero suspicious domain", True, url_result("new-site.example", "NRD_24H")),
        ("New domain with brand lure", True, url_result("sbi-kyc-update.xyz", "NRD_24H")),
        ("Current exact phishing URL", True, url_result("listed.example", "TI_URL_EXACT")),
        ("Confusable brand label", True, url_result("paypa1.com", age_confirmed=False)),
        ("Normal password form", False, page_result('<form action="/session"><input type="password"></form>')),
        ("Password form with foreign destination", True, page_result(
            '<form action="https://other.example/ingest"><input type="password"></form>'
        )),
        ("Ordinary email with a link", False, analyze_raw_email(
            "From: announcements@example.com\nSubject: Report\n\nRead https://example.com/report"
        )),
        ("Email with mismatched displayed link", True, analyze_raw_email(
            "From: testing@example.com\nContent-Type: text/html\n\n"
            '<a href="https://other.example/">https://example.com/</a>'
        )),
    ]
    counts = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    rows = []
    for name, expected, result in cases:
        flagged = result["verdict"] in {"MALICIOUS", "SUSPICIOUS"}
        counts["tp" if expected and flagged else "fn" if expected else "fp" if flagged else "tn"] += 1
        rows.append({"fixture": name, "expected_review": expected, "verdict": result["verdict"], "score": result["risk_score"]})
    print(json.dumps({
        "dataset": "Synthetic regression fixtures",
        "cases": len(cases),
        "precision": round(counts["tp"] / (counts["tp"] + counts["fp"]), 3),
        "recall": round(counts["tp"] / (counts["tp"] + counts["fn"]), 3),
        "confusion_matrix": counts,
        "results": rows,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
