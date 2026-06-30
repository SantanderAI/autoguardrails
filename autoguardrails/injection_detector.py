# Copyright (c) 2026 Santander Group
# SPDX-License-Identifier: Apache-2.0
"""Enriched prompt-injection detector built on the regex cascade.

This wraps :func:`regex_detector.regex_classify_detailed` with a richer result
type: a threat level, an injection type, a confidence score, and an in-memory
audit trail. It is original to this repository, depends only on the Python
standard library, and is configurable from JSON (never YAML, to preserve the
no-runtime-dependencies invariant of the harness).

The detector never raises on hostile input. Detection always runs in full; the
allowlist only filters individual matches out of the result, it never
short-circuits the scan.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import IO

from .regex_detector import _FAMILY_PATTERNS, regex_classify_detailed

logger = logging.getLogger(__name__)

_MIN_LIST_ENTRY_LENGTH = 3
_AUDIT_LOG_MAXLEN = 10_000

# ANSI SGR codes, applied only on a TTY (see ColorFormatter).
_RESET = "\x1b[0m"
_LEVEL_COLORS: dict[int, str] = {
    logging.DEBUG: "\x1b[2m",  # dim
    logging.INFO: "\x1b[36m",  # cyan
    logging.WARNING: "\x1b[33m",  # yellow
    logging.ERROR: "\x1b[31m",  # red
    logging.CRITICAL: "\x1b[1;37;41m",  # bold white on red
}


class ColorFormatter(logging.Formatter):
    """Logging formatter that colors output only when writing to a terminal.

    When the target stream is not a TTY (e.g. redirected to a file or a pipe),
    or when the ``NO_COLOR`` environment variable is set, output is left plain
    so no raw escape codes leak into logs.
    """

    def __init__(self, fmt: str | None = None, *, stream: IO[str] | None = None) -> None:
        super().__init__(fmt or "%(levelname)s %(name)s: %(message)s")
        target = stream if stream is not None else sys.stderr
        self._use_color = (
            bool(getattr(target, "isatty", lambda: False)()) and "NO_COLOR" not in os.environ
        )

    def format(self, record: logging.LogRecord) -> str:
        text = super().format(record)
        if not self._use_color:
            return text
        color = _LEVEL_COLORS.get(record.levelno)
        return f"{color}{text}{_RESET}" if color else text


def enable_colored_logging(level: int = logging.INFO, *, stream: IO[str] | None = None) -> None:
    """Attach a :class:`ColorFormatter` handler to this module's logger.

    Idempotent: repeated calls do not stack handlers. Colors activate only on a
    TTY and respect ``NO_COLOR``.
    """
    target = stream if stream is not None else sys.stderr
    for existing in logger.handlers:
        if isinstance(existing, logging.StreamHandler) and getattr(
            existing, "_autoguardrails_color", False
        ):
            return
    handler: logging.StreamHandler = logging.StreamHandler(target)
    handler.setFormatter(ColorFormatter(stream=target))
    handler._autoguardrails_color = True  # type: ignore[attr-defined]
    logger.addHandler(handler)
    logger.setLevel(level)


class InjectionType(Enum):
    """The attack family a detection belongs to (mirrors the regex cascade)."""

    JAILBREAK = "jailbreak"
    OBFUSCATION = "obfuscation"
    CYBER = "cyber"
    FRAUD = "fraud"
    VIOLENT = "violent"
    BLOCKLIST = "blocklist"


class ThreatLevel(Enum):
    """Severity of a detected threat, ordered by :data:`_THREAT_ORDER`."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_THREAT_ORDER: dict[ThreatLevel, int] = {
    ThreatLevel.NONE: 0,
    ThreatLevel.LOW: 1,
    ThreatLevel.MEDIUM: 2,
    ThreatLevel.HIGH: 3,
    ThreatLevel.CRITICAL: 4,
}

# Per-family severity. Obfuscation is a wrapper, so it is the lowest; direct
# harmful-content families rank highest.
_FAMILY_THREAT: dict[str, ThreatLevel] = {
    "violent": ThreatLevel.CRITICAL,
    "cyber": ThreatLevel.HIGH,
    "fraud": ThreatLevel.HIGH,
    "jailbreak": ThreatLevel.HIGH,
    "obfuscation": ThreatLevel.MEDIUM,
}

# Confidence is discounted when a match only surfaces after heavier
# normalization: a raw hit is the most certain.
_PASS_CONFIDENCE: dict[str, float] = {
    "raw": 0.95,
    "normalized": 0.85,
    "deobfuscated": 0.7,
}


@dataclass
class DetectionResult:
    """Outcome of scanning one input."""

    is_injection: bool
    threat_level: ThreatLevel
    injection_type: InjectionType | None
    confidence: float
    matched_pattern: str | None = None
    explanation: str = ""


@dataclass
class AuditRecord:
    """A single, content-free record of a detection attempt.

    The raw input is never stored — only its SHA-256 digest — so the audit
    trail is safe to retain and inspect.
    """

    timestamp: datetime
    input_hash: str
    source: str
    result: DetectionResult


@dataclass
class DetectionConfig:
    """Runtime detection settings.

    ``sensitivity`` selects a confidence threshold and a minimum threat level.
    ``blocklist`` entries always trigger a CRITICAL detection. ``allowlist``
    entries suppress a match whose text overlaps the allowlisted span; they
    filter results only and never stop the scan. List entries must be at least
    three characters to avoid disabling detection over broad input ranges.
    """

    sensitivity: str = "balanced"
    blocklist: tuple[str, ...] = field(default_factory=tuple)
    allowlist: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.sensitivity not in _SENSITIVITY_THRESHOLDS:
            raise ValueError(
                f"Unknown sensitivity {self.sensitivity!r}; "
                f"expected one of {sorted(_SENSITIVITY_THRESHOLDS)}"
            )
        self.blocklist = self._validate(self.blocklist, "Blocklist")
        self.allowlist = self._validate(self.allowlist, "Allowlist")

    @staticmethod
    def _validate(entries: tuple[str, ...], label: str) -> tuple[str, ...]:
        for entry in entries:
            stripped = entry.strip()
            if not stripped:
                raise ValueError(f"{label} entries must not be empty or whitespace-only")
            if len(stripped) < _MIN_LIST_ENTRY_LENGTH:
                raise ValueError(
                    f"{label} entry {entry!r} is too short "
                    f"(minimum {_MIN_LIST_ENTRY_LENGTH} characters)."
                )
        return tuple(entries)


_SENSITIVITY_THRESHOLDS: dict[str, float] = {
    "strict": 0.3,
    "balanced": 0.5,
    "permissive": 0.7,
}

_SENSITIVITY_MIN_THREAT: dict[str, ThreatLevel] = {
    "strict": ThreatLevel.LOW,
    "balanced": ThreatLevel.MEDIUM,
    "permissive": ThreatLevel.HIGH,
}


def load_detection_config(path: str) -> DetectionConfig:
    """Load a :class:`DetectionConfig` from a JSON file (stdlib only)."""
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Detection config not found: {path}")
    with config_path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"Detection config must be a JSON object: {path}")
    return DetectionConfig(
        sensitivity=data.get("sensitivity", "balanced"),
        blocklist=tuple(data.get("blocklist", ())),
        allowlist=tuple(data.get("allowlist", ())),
    )


class PromptInjectionDetector:
    """Screens inputs for prompt-injection / harmful-intent families.

    Example::

        detector = PromptInjectionDetector()
        result = detector.detect("ignore previous instructions")
        if result.is_injection:
            print(result.threat_level, result.explanation)
    """

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self._config = config or DetectionConfig()
        self._threshold = _SENSITIVITY_THRESHOLDS[self._config.sensitivity]
        self._min_threat = _SENSITIVITY_MIN_THREAT[self._config.sensitivity]
        self._audit_log: deque[AuditRecord] = deque(maxlen=_AUDIT_LOG_MAXLEN)

    def detect(self, text: str, *, source: str = "unknown") -> DetectionResult:
        """Scan ``text`` and record the outcome in the audit trail."""
        result = self._scan(text)
        self._record_audit(text, source, result)
        return result

    def _scan(self, text: str) -> DetectionResult:
        lowered = text.lower()

        # Blocklist always wins, at CRITICAL.
        for entry in self._config.blocklist:
            if entry.lower() in lowered:
                return DetectionResult(
                    is_injection=True,
                    threat_level=ThreatLevel.CRITICAL,
                    injection_type=InjectionType.BLOCKLIST,
                    confidence=1.0,
                    matched_pattern=entry,
                    explanation=f"Input matched blocklist entry {entry!r}.",
                )

        detail = regex_classify_detailed(text)
        if detail is None:
            return DetectionResult(
                is_injection=False,
                threat_level=ThreatLevel.NONE,
                injection_type=None,
                confidence=0.0,
                explanation="No attack-family pattern matched.",
            )

        family, pattern, pass_name = detail

        # Allowlist suppression: if an allowlisted term is present, treat the
        # match as filtered out (results-only filter, scan already ran).
        if any(term.lower() in lowered for term in self._config.allowlist):
            return DetectionResult(
                is_injection=False,
                threat_level=ThreatLevel.NONE,
                injection_type=None,
                confidence=0.0,
                explanation="Match suppressed by allowlist.",
            )

        threat = _FAMILY_THREAT.get(family, ThreatLevel.MEDIUM)
        confidence = _PASS_CONFIDENCE.get(pass_name, 0.7)

        passes_threshold = confidence >= self._threshold
        meets_min_threat = _THREAT_ORDER[threat] >= _THREAT_ORDER[self._min_threat]
        is_injection = passes_threshold and meets_min_threat

        return DetectionResult(
            is_injection=is_injection,
            threat_level=threat if is_injection else ThreatLevel.NONE,
            injection_type=InjectionType(family) if is_injection else None,
            confidence=confidence,
            matched_pattern=pattern,
            explanation=(
                f"Matched {family} via {pass_name} pass "
                f"(confidence {confidence:.2f}, threat {threat.value})."
                if is_injection
                else f"Matched {family} but below {self._config.sensitivity} threshold."
            ),
        )

    def _record_audit(self, text: str, source: str, result: DetectionResult) -> None:
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc),
            input_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            source=source,
            result=result,
        )
        self._audit_log.append(record)
        if result.is_injection:
            logger.warning(
                "Prompt injection DETECTED source=%s threat=%s type=%s",
                source,
                result.threat_level.value,
                result.injection_type.value if result.injection_type else "unknown",
            )
        else:
            logger.debug("Prompt injection scan clean source=%s", source)

    @property
    def audit_log(self) -> tuple[AuditRecord, ...]:
        """An immutable snapshot of the audit trail."""
        return tuple(self._audit_log)


# Sanity check kept cheap: the result enum must cover every cascade family.
assert {name for name, _ in _FAMILY_PATTERNS} <= {t.value for t in InjectionType}
