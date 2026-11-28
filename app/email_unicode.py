"""Offline identity comparisons using the Unicode 18 confusables data (Unicode License v3)."""
import json
import re
import unicodedata as ud
from functools import lru_cache
from pathlib import Path

import idna

INVISIBLE = frozenset("\u200b\u200c\u200d\u00ad\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\ufeff")
STRIP = {ord(c): None for c in INVISIBLE}


def canonical_text(raw):
    return ud.normalize("NFKC", raw.translate(STRIP))


def codepoints(raw):
    return [f"{ud.name(c, 'UNNAMED')} (U+{ord(c):04X})" for c in dict.fromkeys(raw) if not c.isascii()]


@lru_cache(maxsize=1)
def confusables():
    rows = json.loads(Path(__file__).with_name("confusables-18.json").read_text())
    return {int(src, 16): "".join(chr(int(c, 16)) for c in dst.split()) for src, dst in rows.items()}


@lru_cache(maxsize=2048)
def skeleton(label):
    """Case-insensitive identity comparison on an NFD confusable-mapping skeleton."""
    decomposed = ud.normalize("NFD", label.lower().translate(STRIP))
    return ud.normalize("NFD", decomposed.translate(confusables())).casefold()


def decode_host(host):
    labels = []
    for label in host.lower().rstrip(".").split("."):
        if label.startswith("xn--"):
            try:
                label = idna.decode(label)
            except idna.IDNAError:
                pass
        labels.append(label)
    return ".".join(labels)


def scripts(token):
    result = set()
    for c in token:
        if not c.isalpha():
            continue
        name = ud.name(c, "")
        for script in ("LATIN", "GREEK", "CYRILLIC", "MATHEMATICAL", "DEVANAGARI", "ARABIC"):
            if script in name:
                result.add(script)
                break
    return result


@lru_cache(maxsize=4096)
def normalized_distance(left, right):
    """Normalized optimal-string-alignment distance, with adjacent transpositions."""
    previous = list(range(len(right) + 1))
    before = previous
    for i, a in enumerate(left, 1):
        row = [i]
        for j, b in enumerate(right, 1):
            best = min(row[-1] + 1, previous[j] + 1, previous[j - 1] + (a != b))
            if i > 1 and j > 1 and a == right[j - 2] and left[i - 2] == b:
                best = min(best, before[j - 2] + 1)
            row.append(best)
        before, previous = previous, row
    return previous[-1] / max(1, len(left), len(right))


def inspect_token(token, targets, *, domain=False):
    """Inspect one label/word. A non-Latin paragraph is never treated as an identifier."""
    if not 2 <= len(token) <= 63:
        return None
    plain = token.lower()
    shape = skeleton(token)
    if plain in targets:
        return None
    for target in sorted(targets):
        other = skeleton(target)
        if shape == other:
            return "EMAIL_HOMOGRAPH", target
    if domain and not token.isascii() and (len(scripts(token)) > 1 or canonical_text(token).isascii()) and re.fullmatch("[a-z0-9-]{3,63}", shape):
        return "EMAIL_HOMOGRAPH", shape
    if domain and shape.isascii():
        for target in sorted(targets):
            other = skeleton(target)
            n = max(len(shape), len(other))
            if len(target) >= 5 and abs(len(shape) - len(other)) <= 1 and normalized_distance(shape, other) <= 1 / n:
                return "EMAIL_TYPO_DOMAIN", target
    return None

def rtl_filename_preview(filename):
    """Preview a simple directional override run. Preserve the original in evidence."""
    return re.sub("\u202e([^\u202c]*)\u202c?", lambda m: canonical_text(m[1])[::-1], filename)
