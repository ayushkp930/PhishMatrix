"""Build a local IOC snapshot from published OpenPhish data and/or a trusted STIX file."""

import argparse
import json
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from app.intel import MAX_FILE_BYTES, parse_openphish, parse_stix, read_bounded, snapshot_document

OPENPHISH_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"


def fetch_openphish() -> str:
    limits = httpx.Timeout(10, connect=4)
    deadline = time.monotonic() + 20
    with httpx.Client(timeout=limits, follow_redirects=False) as client:
        with client.stream("GET", OPENPHISH_URL, headers={"Accept-Encoding": "identity"}) as response:
            response.raise_for_status()
            if response.headers.get("content-encoding", "identity").lower() != "identity":
                raise ValueError("Unexpected feed encoding.")
            data = bytearray()
            for chunk in response.iter_bytes(16384):
                if time.monotonic() >= deadline:
                    raise TimeoutError("Feed download deadline exceeded.")
                data.extend(chunk)
                if len(data) > MAX_FILE_BYTES:
                    raise ValueError("Feed exceeds the download size limit.")
            return data.decode("utf-8")


def save_snapshot(path: Path, document: dict) -> None:
    payload = json.dumps(document, ensure_ascii=True, separators=(",", ":")).encode()
    if len(payload) > MAX_FILE_BYTES:
        raise ValueError("Generated snapshot exceeds the size limit.")
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".intel-", delete=False) as temp:
            temp_path = Path(temp.name)
            temp.write(payload)
            temp.flush()
            os.fsync(temp.fileno())
        temp_path.replace(path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openphish", action="store_true", help="Download the official community feed.")
    parser.add_argument("--stix", type=Path, help="Import a local, trusted STIX 2.1 bundle.")
    parser.add_argument("--output", type=Path, default=Path("intel-snapshot.json"))
    args = parser.parse_args()
    if not args.openphish and args.stix is None:
        parser.error("Choose --openphish, --stix, or both.")
    now = datetime.now(timezone.utc)
    try:
        records = []
        if args.openphish:
            community = parse_openphish(fetch_openphish(), now)
            if not community:
                raise ValueError("OpenPhish returned no usable indicators.")
            records.extend(community)
        if args.stix:
            imported = parse_stix(json.loads(read_bounded(args.stix)), now)
            if not imported:
                raise ValueError("STIX bundle contained no supported active indicators.")
            records.extend(imported)
        document = snapshot_document(records, now)
        save_snapshot(args.output, document)
    except (httpx.HTTPError, OSError, ValueError) as error:
        parser.exit(1, f"Snapshot refresh failed: {error}\n")
    print(f"Saved {len(document['indicators'])} indicators to {args.output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
