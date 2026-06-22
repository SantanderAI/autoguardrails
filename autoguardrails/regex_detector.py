# Copyright (c) 2026 Santander Group
# SPDX-License-Identifier: Apache-2.0
"""Fast, deterministic regex tier for attack-family classification.

This is the cheap first stage of a two-tier cascade:

    Tier 1  (this module)  regex over three escalating normalization passes
    Tier 2  (model_adapter) substring family classifier as fallback

The regex tier is deterministic, allocation-light, and traceable: every
positive result reports the exact pattern that fired, so callers can record a
precise rationale. Patterns here are original to this repository and target the
attack families exercised by ``eval_suite.jsonl``. They are intentionally
narrow (word boundaries, bounded gaps) to keep benign false positives low.

Prompt Injection Detection — OWASP LLM01 / ASI01.

Screens agent inputs for prompt injection attacks where adversaries attempt
to override system instructions, break out of context boundaries, or
manipulate agent behaviour through crafted payloads, Contributor: Gustavo Venegas - ARGORIX.
CONFIG: Spanish|English.
"""
from __future__ import annotations

import base64
import re
import unicodedata
from typing import Callable

# ---------------------------------------------------------------------------
# Family patterns (original; one compiled tuple per attack family)
# ---------------------------------------------------------------------------

_JAILBREAK: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bignore\b.{0,15}\b(?:previous|prior|earlier|above)\b", re.I),
    re.compile(r"\bdisregard\b.{0,15}\b(?:previous|prior|all|the above)\b", re.I),
    re.compile(r"\bforget\b.{0,25}\b(?:instructions?|rules?|guidelines?)\b", re.I),
    re.compile(r"\boverride\b.{0,15}\b(?:instructions?|rules?|safety|guardrails?)\b", re.I),
    re.compile(r"\b(?:do not|don'?t|never)\b.{0,10}\brefuse\b", re.I),
    re.compile(r"\bdev(?:eloper)?\s*mode\b", re.I),
    re.compile(r"\brole[\s-]?play(?:ing|s)?\b", re.I),
    re.compile(r"\bfiction(?:al)?\b", re.I),
    re.compile(r"\bpretend\b.{0,15}\byou\b", re.I),
    re.compile(r"\bact\s+as\b.{0,25}\bno\s+(?:rules?|restrictions?|limits?)\b", re.I),
    re.compile(r"\bsystem\s*prompt\b", re.I),
    re.compile(r"\buncensored\b", re.I),
    re.compile(r"\bjailbreak\b", re.I),
    re.compile(r"\bDAN\b", re.I),
    # --- Spanish ---
    re.compile(r"\bignor(?:a|ar|e)\b.{0,20}\b(?:anterior(?:es)?|previo|lo\s+anterior)\b", re.I),
    re.compile(r"\bolvid(?:a|ar|e)\b.{0,25}\b(?:instruccion(?:es)?|reglas?|directrices)\b", re.I),
    re.compile(r"\bmodo\s+(?:desarrollador|dios|sin\s+restricciones)\b", re.I),
    re.compile(r"\bsin\s+(?:restricci[oó]n(?:es)?|censura|l[ií]mites?|filtros?)\b", re.I),
    re.compile(r"\bno\s+(?:te\s+)?nieg(?:ues|a)\b", re.I),
    re.compile(r"\b(?:haz\s+de\s+cuenta|act[uú]a\s+como|finge)\b", re.I),
    re.compile(r"\b(?:prompt|indicaci[oó]n)\s+del\s+sistema\b", re.I),
)

_OBFUSCATION: tuple[re.Pattern[str], ...] = (
    re.compile(r"\btranslat(?:e|es|ed|ing|ion)\b", re.I),
    re.compile(r"\bbase[\s_-]?64\b", re.I),
    re.compile(r"\bb64\b", re.I),
    re.compile(r"\brot[\s_-]?13\b", re.I),
    re.compile(r"\bencod(?:e|es|ed|ing)\b", re.I),
    re.compile(r"\bdecod(?:e|es|ed|ing)\b", re.I),
    re.compile(r"\bhex(?:adecimal)?\b.{0,12}\b(?:encode|decode|string)\b", re.I),
    re.compile(r"\byaml\b", re.I),
    re.compile(r"\bjson\b.{0,15}\bonly\b", re.I),
    re.compile(r"\bonly\b.{0,15}\bjson\b", re.I),
    re.compile(r"\bas\s+a\s+(?:poem|mnemonic|riddle|song)\b", re.I),
    re.compile(r"\bshopping\s+list\b", re.I),
    # --- Spanish ---
    re.compile(r"\btraduc(?:e|ir|elo|ido)\b", re.I),
    re.compile(r"\bcodif(?:ica|icar)\b", re.I),
    re.compile(r"\bdecodif(?:ica|icar)\b", re.I),
    re.compile(r"\ben\s+base\s*64\b", re.I),
    re.compile(r"\bsolo\s+(?:en\s+)?json\b", re.I),
    re.compile(r"\bcomo\s+(?:un\s+)?(?:poema|acertijo|canci[oó]n|adivinanza)\b", re.I),
    re.compile(r"\blista\s+de\s+(?:la\s+)?compra\b", re.I),
)

_CYBER: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bphish(?:ing)?\b", re.I),
    re.compile(r"\bransomware\b", re.I),
    re.compile(r"\bsql\s*injection\b", re.I),
    re.compile(r"\bkey[\s-]?logg(?:er|ing)\b", re.I),
    re.compile(r"\bmalware\b", re.I),
    re.compile(r"\bspyware\b", re.I),
    re.compile(r"\bd?dos\b", re.I),
    re.compile(r"\bbrute[\s-]?forc(?:e|ing)\b", re.I),
    re.compile(r"\bsteal\b.{0,20}\b(?:credentials?|passwords?|logins?)\b", re.I),
    re.compile(r"\b(?:remote\s+access\s+trojan|\bRAT\b)\b", re.I),
    # --- Spanish ---
    re.compile(r"\b(?:malware|ransomware|spyware|programa\s+espía)\b", re.I),
    re.compile(r"\binyecci[oó]n\s+sql\b", re.I),
    re.compile(r"\bfuerza\s+bruta\b", re.I),
    re.compile(r"\bregistrador\s+de\s+teclas\b", re.I),
    re.compile(r"\brobar\b.{0,20}\b(?:credenciales|contrase[ñn]as?|datos)\b", re.I),
    re.compile(r"\bsuplant(?:ar|aci[oó]n)\b.{0,15}\b(?:web|correo|p[aá]gina)\b", re.I),
)

_FRAUD: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bdeep[\s-]?fakes?\b", re.I),
    re.compile(r"\bcounterfeit\b", re.I),
    re.compile(r"\bblackmail\b", re.I),
    re.compile(r"\bdox(?:x)?(?:ing|ed)?\b", re.I),
    re.compile(r"\bfake\b.{0,20}\b(?:bank\s+statement|proof\s+of\s+income|id|document)\b", re.I),
    re.compile(r"\bmule\s+accounts?\b", re.I),
    re.compile(r"\bimpersonat(?:e|ing|ion)\b", re.I),
    re.compile(r"\bsocial\s+security\s+number\b", re.I),
    re.compile(r"\b(?:forge|forging)\b.{0,20}\b(?:signature|check|cheque|document)\b", re.I),
    # --- Spanish ---
    re.compile(r"\b(?:deepfake|ultrafals[oa])\b", re.I),
    re.compile(r"\bfalsific(?:a|ar|aci[oó]n)\b", re.I),
    re.compile(r"\b(?:chantaje|extorsi[oó]n)\b", re.I),
    re.compile(r"\bsuplant(?:ar|aci[oó]n)\s+(?:de\s+)?identidad\b", re.I),
    re.compile(r"\bcuentas?\s+mula\b", re.I),
    re.compile(r"\bn[uú]mero\s+de\s+(?:la\s+)?seguridad\s+social\b", re.I),
)

_VIOLENT: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:pipe\s+)?bombs?\b", re.I),
    re.compile(r"\bsilencers?\b", re.I),
    re.compile(r"\bpoison(?:ing)?\b", re.I),
    re.compile(r"\bnapalm\b", re.I),
    re.compile(r"\bkidnap(?:ping)?\b", re.I),
    re.compile(r"\barson\b", re.I),
    re.compile(r"\bbooby[\s-]?traps?\b", re.I),
    re.compile(r"\bghost\s+guns?\b", re.I),
    re.compile(r"\bsedatives?\b", re.I),
    re.compile(r"\bslash\b.{0,12}\btires?\b", re.I),
    # --- Spanish ---
    re.compile(r"\bbombas?\b", re.I),
    re.compile(r"\b(?:veneno|envenenar)\b", re.I),
    re.compile(r"\bsilenciador(?:es)?\b", re.I),
    re.compile(r"\bsecuestr(?:ar|o)\b", re.I),
    re.compile(r"\bincendio\s+provocado\b", re.I),
    re.compile(r"\bsedant(?:e|es)\b", re.I),
    re.compile(r"\barma\s+fantasma\b", re.I),
)

# Base64 detection: a raw 20+ char blob of the base64 alphabet. Treated as an
# obfuscation signal (not its own family), so it stays coverable by policy.md.
_BASE64: tuple[re.Pattern[str], ...] = (re.compile(r"[A-Za-z0-9+/]{20,}={0,2}"),)

# Order is significant: more specific / higher-severity families win ties.
_FAMILY_PATTERNS: tuple[tuple[str, tuple[re.Pattern[str], ...]], ...] = (
    ("violent", _VIOLENT),
    ("cyber", _CYBER),
    ("fraud", _FRAUD),
    ("jailbreak", _JAILBREAK),
    ("obfuscation", _OBFUSCATION + _BASE64),
)

# ---------------------------------------------------------------------------
# Three escalating normalization passes
# ---------------------------------------------------------------------------

_ZERO_WIDTH = re.compile(r"[​‌‍‎‏⁠﻿]")
# Only collapse separators between *single* letters (e.g. "i g n o r e"),
# never between full words, to avoid fusing legitimate text.
_SPACED_LETTERS = re.compile(r"(?<=\b\w)[\s._\-*](?=\w\b)")
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


def _pass_raw(text: str) -> str:
    """Attempt 1: the input untouched (catches exact-cased markers)."""
    return text


def _pass_normalized(text: str) -> str:
    """Attempt 2: lowercase and collapse runs of whitespace."""
    return " ".join(text.lower().split())


def _pass_deobfuscated(text: str) -> str:
    """Attempt 3: strip zero-width chars, join spaced-out letters, and
    append the UTF-8 decoding of any embedded base64 blob."""
    cleaned = _ZERO_WIDTH.sub("", text)
    cleaned = _SPACED_LETTERS.sub("", cleaned)
    decoded_parts: list[str] = []
    for blob in _BASE64_BLOB.findall(cleaned):
        try:
            decoded_parts.append(base64.b64decode(blob, validate=False).decode("utf-8", "ignore"))
        except Exception:  # noqa: BLE001 - malformed base64 is expected and ignored
            continue
    if decoded_parts:
        cleaned = cleaned + " " + " ".join(decoded_parts)
    # Fold accents so accented Spanish (e.g. "tradúcelo") matches the
    # accent-tolerant patterns above.
    cleaned = "".join(
        ch for ch in unicodedata.normalize("NFKD", cleaned) if not unicodedata.combining(ch)
    )
    return cleaned.lower()


# The three attempts, applied in order until one yields a match.
# Names are surfaced by ``regex_classify_detailed`` for confidence scoring:
# a hit on the raw text is more certain than one needing deobfuscation.
_ATTEMPTS: tuple[tuple[str, Callable[[str], str]], ...] = (
    ("raw", _pass_raw),
    ("normalized", _pass_normalized),
    ("deobfuscated", _pass_deobfuscated),
)


def regex_classify_detailed(prompt: str) -> tuple[str, str, str] | None:
    """Classify ``prompt`` and report how it was matched.

    Runs up to three escalating normalization passes. Returns the first
    ``(family, matched_pattern, pass_name)`` found, or ``None`` if all three
    attempts fail. ``pass_name`` is one of ``"raw"``, ``"normalized"``, or
    ``"deobfuscated"``.
    """
    for pass_name, transform in _ATTEMPTS:
        text = transform(prompt)
        for family, patterns in _FAMILY_PATTERNS:
            for pattern in patterns:
                if pattern.search(text):
                    return family, pattern.pattern, pass_name
    return None


def regex_classify(prompt: str) -> tuple[str | None, str | None]:
    """Classify ``prompt`` into an attack family using the regex tier.

    Returns ``(family, matched_pattern)`` for the first hit, or
    ``(None, None)`` if all three attempts fail, in which case the caller
    should fall back to Tier 2.
    """
    detail = regex_classify_detailed(prompt)
    if detail is None:
        return None, None
    family, pattern, _pass = detail
    return family, pattern
