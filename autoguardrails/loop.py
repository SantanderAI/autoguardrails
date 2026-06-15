# Copyright (c) 2026 Santander Group
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .config import DEFAULT_RESULTS_HEADER, ProjectPaths, ResearchConfig
from .eval_runner import load_eval_suite, repeat_evaluation
from .judge import Judge
from .model_adapter import ChatModel
from .schema import RepeatedEvaluationSummary

IGNORED_PARTS = {
    ".autoguardrails",
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}
IGNORED_SUFFIXES = {".pyc", ".pyo"}
KEEP_STATUSES = {"baseline", "accepted"}


class SurfaceDriftError(RuntimeError):
    """Raised when anything outside the mutable surface changes."""


class BaselineRequiredError(RuntimeError):
    """Raised when a candidate run starts before a baseline exists."""


class CandidateUnchangedError(RuntimeError):
    """Raised when the current policy is identical to the last accepted policy."""


@dataclass(frozen=True)
class ResultRow:
    iteration: int
    asr: float
    benign_pass: float
    status: str
    notes: str


@dataclass(frozen=True)
class LoopDecision:
    status: str
    reason: str
    summary: RepeatedEvaluationSummary


class ResearchLoop:
    def __init__(
        self,
        paths: ProjectPaths,
        target_model: ChatModel,
        judge: Judge,
        config: ResearchConfig | None = None,
    ) -> None:
        self.paths = paths
        self.target_model = target_model
        self.judge = judge
        self.config = config or ResearchConfig()
        self._ensure_scaffold_files()

    def run_baseline(self, notes: str = "", repeats: int = 1, reset: bool = False) -> LoopDecision:
        if reset:
            self.paths.results.write_text(DEFAULT_RESULTS_HEADER, encoding="utf-8")
        elif self.load_results():
            raise RuntimeError(
                "Baseline already exists. Use --reset to start over from the current policy."
            )

        summary = self.evaluate_policy_file(self.paths.policy, repeats=repeats)
        if repeats > 1 and not summary.stable:
            raise RuntimeError(
                "Baseline runs were unstable. Investigate the harness before continuing."
            )
        self.paths.state_dir.mkdir(exist_ok=True)
        self.paths.accepted_policy.write_text(
            self.paths.policy.read_text(encoding="utf-8"), encoding="utf-8"
        )
        self.write_protected_manifest()
        self.append_result("baseline", summary, self._compose_notes(notes, "baseline recorded"))
        return LoopDecision(status="baseline", reason="Baseline recorded.", summary=summary)

    def run_candidate(self, notes: str = "", repeats: int = 2) -> LoopDecision:
        if not self.paths.accepted_policy.exists() or not self.paths.protected_manifest.exists():
            raise BaselineRequiredError("Run a baseline before evaluating a candidate policy.")

        self.assert_protected_surface_unchanged()
        candidate_text = self.paths.policy.read_text(encoding="utf-8")
        accepted_text = self.paths.accepted_policy.read_text(encoding="utf-8")
        if normalize_text(candidate_text) == normalize_text(accepted_text):
            raise CandidateUnchangedError(
                "policy.md matches the last accepted policy. Edit policy.md before running candidate."
            )

        summary = self.evaluate_policy_file(self.paths.policy, repeats=repeats)
        current_best = self.current_best_result()
        if current_best is None:
            raise BaselineRequiredError("No kept baseline found in results.tsv.")

        status, reason = self.decide_candidate(
            summary, current_best, candidate_text, accepted_text, repeats
        )
        if status == "accepted":
            self.paths.accepted_policy.write_text(candidate_text, encoding="utf-8")
        else:
            self.paths.policy.write_text(accepted_text, encoding="utf-8")
        self.append_result(status, summary, self._compose_notes(notes, reason))
        self.assert_protected_surface_unchanged()
        return LoopDecision(status=status, reason=reason, summary=summary)

    def evaluate_policy_file(
        self, policy_path: Path, repeats: int = 1
    ) -> RepeatedEvaluationSummary:
        policy_text = policy_path.read_text(encoding="utf-8")
        cases = load_eval_suite(self.paths.eval_suite)
        return repeat_evaluation(
            cases=cases,
            policy_text=policy_text,
            model=self.target_model,
            judge=self.judge,
            config=self.config,
            repeats=repeats,
        )

    def current_best_result(self) -> ResultRow | None:
        kept = [row for row in self.load_results() if row.status in KEEP_STATUSES]
        if not kept:
            return None
        return kept[-1]

    def decide_candidate(
        self,
        summary: RepeatedEvaluationSummary,
        current_best: ResultRow,
        candidate_text: str,
        accepted_text: str,
        repeats: int,
    ) -> tuple[str, str]:
        if repeats > 1 and not summary.stable:
            return "discarded", "repeated runs were unstable"

        benign_floor = current_best.benign_pass - self.config.benign_tolerance
        if summary.benign_pass < benign_floor:
            return (
                "discarded",
                "benign pass fell more than 2 percentage points below the current best",
            )

        if summary.asr < current_best.asr:
            return "accepted", "lower ASR with benign pass inside the allowed floor"

        tied_asr = abs(summary.asr - current_best.asr) <= self.config.tie_tolerance
        tied_benign = (
            abs(summary.benign_pass - current_best.benign_pass) <= self.config.tie_tolerance
        )
        if (
            tied_asr
            and tied_benign
            and policy_complexity(candidate_text) < policy_complexity(accepted_text)
        ):
            return "accepted", "scores were effectively equal and the candidate policy is simpler"

        return "discarded", "candidate did not beat the current best ASR"

    def append_result(self, status: str, summary: RepeatedEvaluationSummary, notes: str) -> None:
        rows = self.load_results()
        iteration = rows[-1].iteration + 1 if rows else 1
        if not self.paths.results.exists():
            self.paths.results.write_text(DEFAULT_RESULTS_HEADER, encoding="utf-8")
        with self.paths.results.open("a", encoding="utf-8") as handle:
            handle.write(
                f"{iteration}\t{summary.asr:.4f}\t{summary.benign_pass:.4f}\t{status}\t{notes}\n"
            )

    def load_results(self) -> list[ResultRow]:
        if not self.paths.results.exists():
            return []
        rows: list[ResultRow] = []
        lines = self.paths.results.read_text(encoding="utf-8").splitlines()
        for raw_line in lines[1:]:
            if not raw_line.strip():
                continue
            parts = raw_line.split("\t", maxsplit=4)
            if len(parts) != 5:
                raise ValueError(f"Invalid results.tsv row: {raw_line}")
            rows.append(
                ResultRow(
                    iteration=int(parts[0]),
                    asr=float(parts[1]),
                    benign_pass=float(parts[2]),
                    status=parts[3],
                    notes=parts[4],
                )
            )
        return rows

    def write_protected_manifest(self) -> None:
        self.paths.state_dir.mkdir(exist_ok=True)
        manifest = snapshot_fixed_surface(self.paths.root)
        self.paths.protected_manifest.write_text(
            json.dumps(manifest, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def assert_protected_surface_unchanged(self) -> None:
        if not self.paths.protected_manifest.exists():
            raise BaselineRequiredError("Protected manifest missing. Re-run baseline.")
        expected = json.loads(self.paths.protected_manifest.read_text(encoding="utf-8"))
        current = snapshot_fixed_surface(self.paths.root)
        if current != expected:
            added = sorted(set(current) - set(expected))
            removed = sorted(set(expected) - set(current))
            changed = sorted(
                path for path in current if path in expected and current[path] != expected[path]
            )
            pieces = []
            if added:
                pieces.append(f"added: {', '.join(added)}")
            if removed:
                pieces.append(f"removed: {', '.join(removed)}")
            if changed:
                pieces.append(f"changed: {', '.join(changed)}")
            message = "; ".join(pieces) if pieces else "unknown surface drift"
            raise SurfaceDriftError(
                "Only policy.md may change between runs. Protected surface drift detected: "
                f"{message}"
            )

    def _ensure_scaffold_files(self) -> None:
        required_files = [
            self.paths.policy,
            self.paths.program,
            self.paths.judge_prompt,
            self.paths.eval_suite,
        ]
        missing = [path.name for path in required_files if not path.exists()]
        if missing:
            raise FileNotFoundError(
                f"Missing required scaffold files: {', '.join(sorted(missing))}"
            )
        if not self.paths.results.exists():
            self.paths.results.write_text(DEFAULT_RESULTS_HEADER, encoding="utf-8")

    def _compose_notes(self, user_notes: str, reason: str) -> str:
        note_parts = [piece for piece in (user_notes.strip(), reason.strip()) if piece]
        return " | ".join(note_parts)


def snapshot_fixed_surface(root: Path) -> dict[str, str]:
    manifest: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if should_ignore_path(relative):
            continue
        manifest[relative] = sha256_file(path)
    return manifest


def should_ignore_path(relative_path: str) -> bool:
    path = Path(relative_path)
    if any(part in IGNORED_PARTS for part in path.parts):
        return True
    if path.suffix in IGNORED_SUFFIXES:
        return True
    return relative_path in {"policy.md", "results.tsv"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def policy_complexity(text: str) -> int:
    return len(" ".join(text.split()))


def normalize_text(text: str) -> str:
    return " ".join(text.split())
