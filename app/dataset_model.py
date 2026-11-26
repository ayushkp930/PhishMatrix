"""Small, inspectable URL model. Inference uses local URL properties only."""

import hashlib
import json
import math
import re
from functools import lru_cache
from pathlib import Path

from app.engines.forensics import registrable_domain

MODEL_PATH = Path(__file__).with_name("url_model.json")
FEATURE_NAMES = (
    "host_length", "host_digits", "host_hyphens", "host_dots", "path_length", "path_depth",
    "query_length", "query_pairs", "encoded_octets", "path_digits", "lure_words",
    "ip_address", "plain_http", "shared_host", "high_risk_suffix",
)


def url_features(target: dict) -> list[float]:
    host, path, query = (target[key] for key in ("domain", "path", "query"))
    return [
        min(len(host), 100), sum(char.isdigit() for char in host), host.count("-"), host.count("."),
        min(len(path), 200), min(path.count("/"), 20), min(len(query), 200), min(query.count("="), 20),
        len(re.findall(r"%[a-fA-F0-9]{2}", path + query)), sum(char.isdigit() for char in path),
        len(re.findall(r"\b(?:login|verify|account|secure|signin|password|wallet|kyc)\b", path + " " + query, re.I)),
        int(bool(re.fullmatch(r"(?:\d+\.){3}\d+", host) or ":" in host)),
        int(target["url"].startswith("http://")),
        int(any(host.endswith("." + suffix) for suffix in ("github.io", "pages.dev", "web.app", "vercel.app", "netlify.app"))),
        int(host.rsplit(".", 1)[-1] in {"top", "xyz", "buzz", "icu", "click", "link", "zip"}),
    ]


def dataset_partition(host: str) -> int:
    root = registrable_domain(host) or host
    return int.from_bytes(hashlib.blake2b(root.encode(), digest_size=8).digest()) % 10


def model_score(features: list[float], model: dict) -> float:
    value = model["intercept"] + sum(weight * feature for weight, feature in zip(model["coefficients"], features, strict=True))
    return 1 / (1 + math.exp(-min(35, max(-35, value))))


@lru_cache(maxsize=1)
def load_model() -> dict:
    return json.loads(MODEL_PATH.read_text(encoding="utf-8"))


def dataset_context(target: dict) -> dict | None:
    try:
        model = load_model()
        value = model_score(url_features(target), model)
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        return None
    return {"score": round(value, 4), "flagged": value >= model["threshold"], "threshold": model["threshold"]}
