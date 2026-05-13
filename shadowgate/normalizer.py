from __future__ import annotations

import base64
import html
import json
import re
import string
import unicodedata
import urllib.parse
from dataclasses import dataclass
from typing import Any, Iterable


ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\ufeff]")
BASE64_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{16,}={0,2})(?![A-Za-z0-9+/=_-])"
)

RISKY_DECODE_MARKERS = [
    "ignore",
    "instructions",
    "system prompt",
    "developer message",
    ".env",
    "secret",
    "token",
    "password",
    "private key",
    "ssh",
    "id_rsa",
    "curl",
    "wget",
    "powershell",
    "169.254.169.254",
    "metadata.google.internal",
]


@dataclass(frozen=True)
class TextVariant:
    name: str
    text: str


def normalize_text(text: str) -> str:
    """
    Normalize text before rule scanning.

    This reduces simple obfuscation such as:
    - zero-width characters
    - Unicode compatibility variants
    - repeated whitespace weirdness
    """
    text = text or ""
    text = unicodedata.normalize("NFKC", text)
    text = ZERO_WIDTH_RE.sub("", text)
    return text


def _safe_url_decode(text: str, rounds: int = 2) -> str:
    current = text or ""

    for _ in range(rounds):
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            break
        current = decoded

    return current


def _json_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _json_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _json_strings(item)


def _extract_json_strings(text: str) -> list[str]:
    try:
        parsed = json.loads(text)
    except Exception:
        return []

    return [item for item in _json_strings(parsed) if item.strip()]


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0

    printable = set(string.printable)
    count = sum(1 for char in text if char in printable or char.isspace())
    return count / max(len(text), 1)


def _looks_security_relevant(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in RISKY_DECODE_MARKERS)


def _safe_base64_decode(candidate: str) -> str | None:
    raw = candidate.strip()

    if len(raw) < 16:
        return None

    padded = raw + ("=" * ((4 - len(raw) % 4) % 4))

    decoders = [
        lambda value: base64.b64decode(value, validate=False),
        lambda value: base64.urlsafe_b64decode(value),
    ]

    for decoder in decoders:
        try:
            decoded_bytes = decoder(padded)
            decoded = decoded_bytes.decode("utf-8", errors="ignore").strip()
        except Exception:
            continue

        if len(decoded) < 8:
            continue

        if _printable_ratio(decoded) < 0.85:
            continue

        if not _looks_security_relevant(decoded):
            continue

        return decoded

    return None


def _add_variant(variants: list[TextVariant], seen: set[str], name: str, text: str) -> None:
    clean = text or ""

    if not clean.strip():
        return

    if clean in seen:
        return

    seen.add(clean)
    variants.append(TextVariant(name=name, text=clean))


def expand_text_variants(text: str, max_variants: int = 30) -> list[TextVariant]:
    """
    Return original + normalized/decoded variants for scanner rules.

    The scanner should still hash and redact the original input, but it should
    also detect suspicious content hidden behind simple encodings.
    """
    original = text or ""

    variants: list[TextVariant] = []
    seen: set[str] = set()

    _add_variant(variants, seen, "original", original)

    normalized = normalize_text(original)
    _add_variant(variants, seen, "normalized", normalized)

    html_decoded = html.unescape(original)
    _add_variant(variants, seen, "html_unescaped", html_decoded)

    url_decoded = _safe_url_decode(original)
    _add_variant(variants, seen, "url_decoded", url_decoded)

    combined = normalize_text(_safe_url_decode(html.unescape(original)))
    _add_variant(variants, seen, "combined_normalized", combined)

    # Extract strings from JSON payloads. MCP arguments are commonly JSON.
    for index, candidate in enumerate(list(variants)):
        for extracted in _extract_json_strings(candidate.text):
            _add_variant(variants, seen, f"json_string_{index}", extracted)
            _add_variant(variants, seen, f"json_string_{index}_normalized", normalize_text(extracted))
            _add_variant(variants, seen, f"json_string_{index}_decoded", _safe_url_decode(html.unescape(extracted)))

    # Decode base64-looking candidates only if the decoded value is printable
    # and security-relevant. This avoids turning random IDs into noisy findings.
    for index, candidate in enumerate(list(variants)):
        for match in BASE64_CANDIDATE_RE.finditer(candidate.text):
            decoded = _safe_base64_decode(match.group(1))
            if decoded:
                _add_variant(variants, seen, f"base64_decoded_{index}", decoded)
                _add_variant(variants, seen, f"base64_decoded_{index}_normalized", normalize_text(decoded))

            if len(variants) >= max_variants:
                return variants[:max_variants]

    return variants[:max_variants]
