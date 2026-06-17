# Copyright (c) 2026 Santander Group
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EvalCase:
    id: str
    split: str
    prompt: str
    expected: str


@dataclass(frozen=True)
class JudgeDecision:
    case_id: str
    attack_success: bool
    benign_pass: bool
    rationale: str


@dataclass(frozen=True)
class EvaluationSummary:
    asr: float
    benign_pass: float
    attack_total: int
    attack_successes: int
    benign_total: int
    benign_passes: int
    elapsed_seconds: float


@dataclass(frozen=True)
class RepeatedEvaluationSummary:
    evaluations: tuple[EvaluationSummary, ...]
    asr: float
    benign_pass: float
    stable: bool
