"""Local exact URL matches against the historical, CC0 Kaggle corpus."""

import hashlib
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

INDEX_PATH = Path(__file__).with_name("kaggle_history.bin")
SOURCE = "Kaggle · Malicious URLs dataset (2021 snapshot)"
LABELS = {1: "phishing", 2: "malware", 4: "defacement"}
KEY_BYTES = 16
RECORD_BYTES = KEY_BYTES + 1


def url_digest(url: str, *, unspecified_scheme: bool = False) -> bytes:
    if unspecified_scheme:
        parts = urlsplit(url)
        url = urlunsplit(("", parts.netloc, parts.path, parts.query, ""))
    return hashlib.sha256(url.encode("utf-8")).digest()[:KEY_BYTES]


@lru_cache(maxsize=1)
def read_index() -> bytes:
    with INDEX_PATH.open("rb") as stream:
        data = stream.read(5 * 1024 * 1024 + 1)
    if not data or len(data) % RECORD_BYTES or len(data) > 5 * 1024 * 1024:
        raise ValueError("Invalid historical IOC index.")
    return data


def label_mask(data: bytes, key: bytes) -> int:
    low, high = 0, len(data) // RECORD_BYTES
    while low < high:
        middle = (low + high) // 2
        start = middle * RECORD_BYTES
        candidate = data[start:start + KEY_BYTES]
        if candidate == key:
            return data[start + KEY_BYTES]
        if candidate < key:
            low = middle + 1
        else:
            high = middle
    return 0


def historical_url_lookup(url: str) -> dict:
    try:
        data = read_index()
    except (OSError, ValueError):
        return {"status": "Unavailable", "scope": "url", "labels": []}
    flags = label_mask(data, url_digest(url)) | label_mask(data, url_digest(url, unspecified_scheme=True))
    labels = [name for mask, name in LABELS.items() if flags & mask]
    return {"status": "Historical match" if labels else "No historical match", "scope": "url", "labels": labels}
