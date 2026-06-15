# Copyright (c) 2026 Santander Group
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import argparse
from pathlib import Path

from .config import ProjectPaths, ResearchConfig, load_endpoint_config
from .judge import build_judge
from .loop import BaselineRequiredError, CandidateUnchangedError, ResearchLoop, SurfaceDriftError
from .model_adapter import build_target_model


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Autoresearch-style guardrail loop.")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Project root containing policy.md and eval_suite.jsonl.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    baseline_parser = subparsers.add_parser(
        "baseline", help="Run the initial baseline and initialize state."
    )
    baseline_parser.add_argument(
        "--notes", default="", help="Free-form note to append to results.tsv."
    )
    baseline_parser.add_argument(
        "--repeat", type=int, default=1, help="How many identical evaluation passes to run."
    )
    baseline_parser.add_argument(
        "--reset", action="store_true", help="Reset results.tsv before writing the baseline."
    )

    candidate_parser = subparsers.add_parser(
        "candidate", help="Evaluate the current policy.md against the last accepted policy."
    )
    candidate_parser.add_argument(
        "--notes", default="", help="Free-form note to append to results.tsv."
    )
    candidate_parser.add_argument(
        "--repeat", type=int, default=2, help="How many identical evaluation passes to run."
    )

    evaluate_parser = subparsers.add_parser(
        "evaluate", help="Evaluate a policy without mutating state."
    )
    evaluate_parser.add_argument(
        "--policy",
        type=Path,
        default=None,
        help="Policy file to score. Defaults to policy.md in the root.",
    )
    evaluate_parser.add_argument(
        "--repeat", type=int, default=1, help="How many identical evaluation passes to run."
    )

    subparsers.add_parser("status", help="Show the current kept result.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    paths = ProjectPaths.discover(args.root)
    loop = ResearchLoop(
        paths=paths,
        target_model=build_target_model(
            load_endpoint_config("TARGET", default_model="stub-target")
        ),
        judge=build_judge(
            load_endpoint_config("JUDGE", default_model="stub-judge"),
            paths.judge_prompt.read_text(encoding="utf-8"),
        ),
        config=ResearchConfig(),
    )

    try:
        if args.command == "baseline":
            decision = loop.run_baseline(notes=args.notes, repeats=args.repeat, reset=args.reset)
            print_decision(decision.status, decision.reason, decision.summary)
            return 0
        if args.command == "candidate":
            decision = loop.run_candidate(notes=args.notes, repeats=args.repeat)
            print_decision(decision.status, decision.reason, decision.summary)
            return 0
        if args.command == "evaluate":
            policy_path = args.policy.resolve() if args.policy else paths.policy
            summary = loop.evaluate_policy_file(policy_path, repeats=args.repeat)
            print_summary(summary)
            return 0
        if args.command == "status":
            row = loop.current_best_result()
            if row is None:
                print("status=uninitialized")
                print("reason=no baseline found")
                return 0
            print("status=ready")
            print(f"iteration={row.iteration}")
            print(f"asr={row.asr:.4f}")
            print(f"benign_pass={row.benign_pass:.4f}")
            print(f"notes={row.notes}")
            return 0
    except (
        BaselineRequiredError,
        CandidateUnchangedError,
        SurfaceDriftError,
        RuntimeError,
        ValueError,
    ) as exc:
        print(f"error={exc}")
        return 1
    return 0


def print_decision(status: str, reason: str, summary) -> None:
    print(f"status={status}")
    print(f"reason={reason}")
    print_summary(summary)


def print_summary(summary) -> None:
    print(f"asr={summary.asr:.4f}")
    print(f"benign_pass={summary.benign_pass:.4f}")
    print(f"stable={'yes' if summary.stable else 'no'}")
    print(f"repeats={len(summary.evaluations)}")
    first = summary.evaluations[0]
    print(f"attack_cases={first.attack_total}")
    print(f"benign_cases={first.benign_total}")
    print(f"elapsed_seconds={sum(item.elapsed_seconds for item in summary.evaluations):.2f}")


if __name__ == "__main__":
    raise SystemExit(main())
