"""Build an offline index from the CC0 sid321axn/malicious-urls-dataset CSV or ZIP."""

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path

from app.historical_intel import INDEX_PATH, LABELS, url_digest
from app.security import normalize_target
from scripts.evaluate_datasets import open_csv

MASKS = {name: bit for bit, name in LABELS.items()}
BENIGN = 8


def build_index(path: Path) -> tuple[bytes, Counter]:
    csv.field_size_limit(256 * 1024)
    records = defaultdict(int)
    counts = Counter()
    with open_csv(path, "malicious_phish.csv") as stream:
        reader = csv.DictReader(stream)
        if not {"url", "type"}.issubset(reader.fieldnames or []):
            raise ValueError("Expected url and type columns.")
        for row in reader:
            value = (row.get("url") or "").strip()
            kind = (row.get("type") or "").strip().lower()
            if kind not in MASKS and kind != "benign":
                continue
            try:
                url = normalize_target(value, resolve=False)["url"]
            except ValueError:
                counts["unsupported"] += 1
                continue
            unspecified = not value.lower().startswith(("http://", "https://", "hxxp://", "hxxps://"))
            digest = url_digest(url, unspecified_scheme=unspecified)
            records[digest] |= MASKS.get(kind, BENIGN)
            counts[kind] += 1
    output = bytearray()
    for key, flags in sorted(records.items()):
        if flags & BENIGN:
            if flags != BENIGN:
                counts["conflicting_keys_omitted"] += 1
            continue
        output.extend(key)
        output.append(flags)
        counts["historical_records"] += 1
    return bytes(output), counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", type=Path, default=INDEX_PATH)
    args = parser.parse_args()
    data, counts = build_index(args.source)
    if not data:
        parser.exit(1, "No supported historical indicators.\n")
    args.output.write_bytes(data)
    print(dict(counts))


if __name__ == "__main__":
    main()
