"""Evaluate passive URL rules on labeled Kaggle CSVs without opening sample URLs."""

import argparse
import csv
import hashlib
import heapq
import io
import json
import sys
from contextlib import contextmanager
from pathlib import Path
from zipfile import ZipFile

from app.dataset_model import dataset_context, dataset_partition
from app.engines.heuristics import lexical_findings
from app.scoring import VERSION, assess
from app.security import normalize_target

DATASETS = {
    "malicious-urls": ("malicious_phish.csv", "type", "phishing", "benign"),
    "extracted-features": ("phishing_features.csv", "label", "1", "0"),
    "url-features-2026": ("final_dataset.csv", "label", "1", "0"),
}
MAX_CSV_SIZE = 600 * 1024 * 1024


@contextmanager
def open_csv(path, member):
    if path.suffix.lower() == ".zip":
        with ZipFile(path) as archive:
            if not member:
                raise ValueError("Pass --csv-member for this ZIP.")
            entry = archive.getinfo(member)
            if entry.file_size > MAX_CSV_SIZE:
                raise ValueError("CSV exceeds 600 MiB.")
            with archive.open(entry) as raw, io.TextIOWrapper(raw, encoding="utf-8-sig", newline="") as source:
                yield source
    else:
        if path.stat().st_size > MAX_CSV_SIZE:
            raise ValueError("CSV exceeds 600 MiB.")
        with path.open(encoding="utf-8-sig", newline="") as source:
            yield source


def evaluate(path, member, label_column, positive, negative, limit, *, model_holdout=False):
    groups = {positive: [], negative: []}
    membership = {positive: set(), negative: set()}
    skipped = 0
    csv.field_size_limit(256 * 1024)
    with open_csv(path, member) as source:
        rows = csv.DictReader(source)
        if not {"url", label_column}.issubset(rows.fieldnames or []):
            raise ValueError(f"Expected url and {label_column} columns.")
        for row in rows:
            value, label = (row.get(key) or "" for key in ("url", label_column))
            value, label = value.strip(), label.strip().lower()
            if label not in groups or not value or len(value) > 2048:
                skipped += 1
                continue
            heap, seen = groups[label], membership[label]
            rank = int.from_bytes(hashlib.blake2b(value.encode(), digest_size=8).digest())
            if value in seen:
                continue
            candidate = (-rank, value)
            if len(heap) < limit:
                heapq.heappush(heap, candidate)
            elif candidate > heap[0]:
                _, removed = heapq.heapreplace(heap, candidate)
                seen.remove(removed)
            else:
                continue
            seen.add(value)

    # Omit conflicting labels where both versions appear in the selected sample.
    conflicts = membership[positive] & membership[negative]
    counts = dict(tp=0, tn=0, fp=0, fn=0, unsupported=0)
    model_counts = dict(tp=0, tn=0, fp=0, fn=0)
    for label, heap in groups.items():
        for _, value in heap:
            if value in conflicts:
                continue
            try:
                target = normalize_target(value, resolve=False)
            except ValueError:
                counts["unsupported"] += 1
                continue
            if model_holdout and dataset_partition(target["domain"]) < 8:
                continue
            model = dataset_context(target)
            if model is not None:
                model_counts["tp" if label == positive and model["flagged"] else "fn" if label == positive else "fp" if model["flagged"] else "tn"] += 1
            findings = lexical_findings(target["domain"], target["path"], target["query"])
            flagged = assess(findings, coverage_sufficient=False)["verdict"] in {"SUSPICIOUS", "MALICIOUS"}
            counts["tp" if label == positive and flagged else "fn" if label == positive else "fp" if flagged else "tn"] += 1
    tp, fp, fn, tn = (counts[key] for key in ("tp", "fp", "fn", "tn"))
    ratio = lambda a, b: round(a / b, 6) if b else None
    mtp, mfp, mfn, mtn = (model_counts[key] for key in ("tp", "fp", "fn", "tn"))
    return {
        "dataset_model": {
            "counts": model_counts,
            "precision": ratio(mtp, mtp + mfp), "recall": ratio(mtp, mtp + mfn),
            "false_positive_rate": ratio(mfp, mfp + mtn), "registered_domain_holdout": model_holdout,
        },
        "evaluated": tp + fp + fn + tn, "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
        "false_positive_rate": ratio(fp, fp + tn), "counts": counts,
        "rows_skipped_before_sampling": skipped, "sample_label_conflicts": len(conflicts),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", type=Path, nargs="+", help="Kaggle ZIP or extracted CSV; pass multiple files to evaluate each separately.")
    parser.add_argument("--per-class", type=int, default=4000)
    parser.add_argument("--csv-member", help="CSV filename within a custom ZIP.")
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--positive", default="1")
    parser.add_argument("--negative", default="0")
    args = parser.parse_args()
    if not 1 <= args.per_class <= 50000 or args.positive.lower() == args.negative.lower():
        parser.error("Choose 1–50,000 rows per class and distinct labels.")
    results = []
    for path in args.inputs:
        key = next((key for key, names in {
            "malicious-urls": {"malicious-urls-dataset", "malicious_phish"},
            "extracted-features": {"phishing-urls-dataset-with-extracted-features", "phishing_features"},
            "url-features-2026": {"phishing-url-features-dataset", "final_dataset"},
        }.items() if path.stem in names), None)
        fields = DATASETS[key] if key else (args.csv_member, args.label_column, args.positive.lower(), args.negative.lower())
        try:
            results.append({"dataset": path.name, **evaluate(path, *fields, args.per_class, model_holdout=True)})
        except (ValueError, KeyError, OSError, csv.Error, UnicodeError) as error:
            print(f"{path.name}: {error}", file=sys.stderr)
            return 1
    print(json.dumps({"version": VERSION, "mode": "offline lexical rules and contextual model; registered-domain holdout", "sample_per_class": args.per_class, "datasets": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
