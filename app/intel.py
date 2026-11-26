"""Exact IOC matching against operator-managed intelligence snapshots."""

import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path

from app.security import normalize_target

MAX_FILE_BYTES = 6 * 1024 * 1024
MAX_RECORDS = 25000
SOURCE_OPENPHISH = "OpenPhish Community"
SOURCE_STIX = "Analyst STIX"
STIX_VALUE = re.compile(r"\[\s*(url|domain-name|ipv4-addr|ipv6-addr):value\s*=\s*'([^'\\]+)'\s*\]")
STIX_KINDS = {"url": "url", "domain-name": "domain", "ipv4-addr": "ip", "ipv6-addr": "ip"}


@dataclass(frozen=True)
class Indicator:
    kind: str
    value: str
    source: str
    expires_at: str


def timestamp(text: str) -> datetime:
    value = datetime.fromisoformat(text)
    if value.tzinfo is None:
        raise ValueError("A timestamp must include a timezone.")
    return value.astimezone(timezone.utc)


def canonical_value(kind: str, value: str) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("Invalid indicator.")
    if kind == "ip":
        return str(ip_address(value))
    if kind == "url" and value.startswith(("http://", "https://")):
        return normalize_target(value, resolve=False)["url"]
    if kind == "domain" and not any(char in value for char in "/?#:@[]"):
        try:
            ip_address(value)
        except ValueError:
            return normalize_target(value, resolve=False)["domain"]
    raise ValueError("Unsupported indicator type or value.")


def parse_openphish(body: str, now: datetime) -> list[Indicator]:
    expires = (now + timedelta(hours=72)).isoformat()
    records = []
    seen = set()
    for line in body.splitlines():
        if len(records) == MAX_RECORDS:
            break
        try:
            value = canonical_value("url", line.strip())
        except ValueError:
            continue
        if value not in seen:
            records.append(Indicator("url", value, SOURCE_OPENPHISH, expires))
            seen.add(value)
    return records


def parse_stix(bundle: dict, now: datetime) -> list[Indicator]:
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("Expected a STIX bundle with an objects array.")
    records = []
    for obj in bundle["objects"][:MAX_RECORDS]:
        if not isinstance(obj, dict) or obj.get("type") != "indicator" or obj.get("pattern_type") != "stix" or obj.get("revoked"):
            continue
        pattern = obj.get("pattern")
        match = STIX_VALUE.fullmatch(pattern) if isinstance(pattern, str) and len(pattern) < 2100 else None
        if not match:
            continue
        try:
            begins = timestamp(obj["valid_from"])
            expires = timestamp(obj["valid_until"]) if "valid_until" in obj else now + timedelta(days=7)
            if not begins <= now < expires:
                continue
            kind = STIX_KINDS[match[1]]
            value = canonical_value(kind, match[2])
            records.append(Indicator(kind, value, SOURCE_STIX, expires.isoformat()))
        except (TypeError, KeyError, ValueError, OverflowError):
            continue
    return records


def read_bounded(path: Path) -> bytes:
    with path.open("rb") as file:
        content = file.read(MAX_FILE_BYTES + 1)
    if len(content) > MAX_FILE_BYTES:
        raise ValueError("Intelligence file exceeds the size limit.")
    return content


def snapshot_document(records: list[Indicator], generated_at: datetime) -> dict:
    unique = list(dict.fromkeys(records))[:MAX_RECORDS]
    return {"version": 1, "generated_at": generated_at.isoformat(), "indicators": [asdict(record) for record in unique]}


@lru_cache(maxsize=4)
def _read_index(path: Path, modified_ns: int, size: int) -> tuple[str, datetime | None, dict]:
    data = json.loads(read_bounded(path))
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("indicators"), list):
        raise ValueError("Unsupported snapshot.")
    generated = timestamp(data["generated_at"])
    index = {}
    latest = None
    for entry in data["indicators"][:MAX_RECORDS]:
        try:
            source = entry["source"]
            if source not in (SOURCE_OPENPHISH, SOURCE_STIX):
                continue
            kind = entry["kind"]
            value = canonical_value(kind, entry["value"])
            expires = timestamp(entry["expires_at"])
        except (TypeError, KeyError, ValueError, OverflowError):
            continue
        sources = index.setdefault((kind, value), {})
        if source not in sources or expires > sources[source]:
            sources[source] = expires
        if latest is None or expires > latest:
            latest = expires
    return generated.isoformat(), latest, index


def lookup_snapshot(url: str, domain: str, ip: str | None) -> dict:
    filename = os.getenv("PHISHMATRIX_INTEL_FILE", "").strip()
    if not filename:
        return {"status": "Not configured", "hits": []}
    path = Path(filename)
    try:
        stat = path.stat()
        generated, latest, index = _read_index(path, stat.st_mtime_ns, stat.st_size)
    except (OSError, TypeError, ValueError, KeyError, OverflowError):
        return {"status": "Unavailable", "hits": []}

    now = datetime.now(timezone.utc)
    if not latest or latest <= now:
        return {"status": "Stale or empty", "hits": [], "snapshot_at": generated}
    hits = []
    for kind, value in (("url", url), ("domain", domain), ("ip", ip)):
        for source, expires in index.get((kind, value), {}).items():
            if expires > now:
                hits.append({"scope": kind, "source": source, "expires_at": expires.isoformat()})
    return {"status": "Match" if hits else "No match", "hits": hits, "snapshot_at": generated}
