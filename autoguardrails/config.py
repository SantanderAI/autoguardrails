# Copyright (c) 2026 Santander Group
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_RESULTS_HEADER = "iteration\tasr\tbenign_pass\tstatus\tnotes\n"


@dataclass(frozen=True)
class EndpointConfig:
    provider: str
    model: str
    api_base: str | None
    api_key: str | None
    max_tokens: int
    temperature: float
    top_p: float
    timeout_seconds: int


@dataclass(frozen=True)
class ResearchConfig:
    wall_clock_seconds: int = 900
    benign_tolerance: float = 0.02
    tie_tolerance: float = 0.005


@dataclass(frozen=True)
class ProjectPaths:
    root: Path
    policy: Path
    program: Path
    judge_prompt: Path
    eval_suite: Path
    results: Path
    state_dir: Path
    accepted_policy: Path
    protected_manifest: Path

    @classmethod
    def discover(cls, root: Path | None = None) -> ProjectPaths:
        base = (root or Path.cwd()).resolve()
        state_dir = base / ".autoguardrails"
        return cls(
            root=base,
            policy=base / "policy.md",
            program=base / "program.md",
            judge_prompt=base / "judge_prompt.md",
            eval_suite=base / "eval_suite.jsonl",
            results=base / "results.tsv",
            state_dir=state_dir,
            accepted_policy=state_dir / "accepted_policy.md",
            protected_manifest=state_dir / "protected_manifest.json",
        )


def load_endpoint_config(prefix: str, default_model: str) -> EndpointConfig:
    env_prefix = f"AUTOGUARDRAILS_{prefix.upper()}_"
    return EndpointConfig(
        provider=os.getenv(f"{env_prefix}PROVIDER", "stub"),
        model=os.getenv(f"{env_prefix}MODEL", default_model),
        api_base=os.getenv(f"{env_prefix}API_BASE"),
        api_key=os.getenv(f"{env_prefix}API_KEY"),
        max_tokens=int(os.getenv(f"{env_prefix}MAX_TOKENS", "256")),
        temperature=float(os.getenv(f"{env_prefix}TEMPERATURE", "0")),
        top_p=float(os.getenv(f"{env_prefix}TOP_P", "1")),
        timeout_seconds=int(os.getenv(f"{env_prefix}TIMEOUT_SECONDS", "60")),
    )
