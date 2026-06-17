# Copyright (c) 2026 Santander Group
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import time
from pathlib import Path

from .config import ResearchConfig
from .judge import Judge
from .model_adapter import ChatModel
from .schema import EvalCase, EvaluationSummary, RepeatedEvaluationSummary


def load_eval_suite(path: Path) -> list[EvalCase]:
    cases: list[EvalCase] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        record = json.loads(line)
        required = {"id", "split", "prompt", "expected"}
        if set(record) != required:
            raise ValueError(
                f"eval_suite line {line_number} must have exactly {required}, got {set(record)}"
            )
        split = record["split"]
        expected = record["expected"]
        if split not in {"attack", "benign"}:
            raise ValueError(f"eval_suite line {line_number} has invalid split: {split}")
        if expected not in {"refuse", "answer"}:
            raise ValueError(f"eval_suite line {line_number} has invalid expected: {expected}")
        cases.append(
            EvalCase(
                id=str(record["id"]),
                split=split,
                prompt=str(record["prompt"]),
                expected=expected,
            )
        )
    return cases


def evaluate_policy(
    cases: list[EvalCase],
    policy_text: str,
    model: ChatModel,
    judge: Judge,
    config: ResearchConfig,
) -> EvaluationSummary:
    start = time.monotonic()
    attack_total = 0
    attack_successes = 0
    benign_total = 0
    benign_passes = 0

    for index, case in enumerate(cases, start=1):
        elapsed = time.monotonic() - start
        if elapsed > config.wall_clock_seconds:
            raise TimeoutError(
                f"Evaluation exceeded the {config.wall_clock_seconds}-second budget after {index - 1} cases."
            )
        response = model.generate(case.prompt, policy_text)
        decision = judge.evaluate(case, response)
        if case.split == "attack":
            attack_total += 1
            attack_successes += int(decision.attack_success)
        else:
            benign_total += 1
            benign_passes += int(decision.benign_pass)

    elapsed_seconds = time.monotonic() - start
    return EvaluationSummary(
        asr=(attack_successes / attack_total) if attack_total else 0.0,
        benign_pass=(benign_passes / benign_total) if benign_total else 0.0,
        attack_total=attack_total,
        attack_successes=attack_successes,
        benign_total=benign_total,
        benign_passes=benign_passes,
        elapsed_seconds=elapsed_seconds,
    )


def repeat_evaluation(
    cases: list[EvalCase],
    policy_text: str,
    model: ChatModel,
    judge: Judge,
    config: ResearchConfig,
    repeats: int,
) -> RepeatedEvaluationSummary:
    if repeats < 1:
        raise ValueError("repeats must be at least 1")
    evaluations = tuple(
        evaluate_policy(cases, policy_text, model, judge, config) for _ in range(repeats)
    )
    stable = len({(round(item.asr, 8), round(item.benign_pass, 8)) for item in evaluations}) == 1
    return RepeatedEvaluationSummary(
        evaluations=evaluations,
        asr=sum(item.asr for item in evaluations) / len(evaluations),
        benign_pass=sum(item.benign_pass for item in evaluations) / len(evaluations),
        stable=stable,
    )
