# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Per-attack-family diagnostics: `baseline`, `candidate`, and `evaluate` now report
  attack success rate broken down by family (ranked leakiest-first) in addition to
  the aggregate `ASR`, turning each iteration into a targeted, one-family-at-a-time
  worklist. Families are derived from the existing harness taxonomy, so the frozen
  evaluation surface (`eval_suite.jsonl`, `judge_prompt.md`) is unchanged.
- Open-source readiness scaffolding:
  - Apache 2.0 `LICENSE` + `NOTICE`, `CONTRIBUTING.md` (CLA), `CODE_OF_CONDUCT.md`,
    `SECURITY.md`, `CODEOWNERS`
  - Issue templates (bug, feature) and PR template
  - `pyproject.toml` tooling config (ruff, black, mypy, pytest, coverage)
  - SPDX headers on Python sources and tests
  - GitHub Actions workflows (third-party actions pinned to SHA digests):
    - `ci.yml` — ruff + black + mypy + pytest matrix (3.10/3.11/3.12) with Codecov
    - `codeql.yml` — CodeQL SAST (push, PR, weekly cron)
    - `dep-scan.yml` — `pip-audit` (push, PR, daily cron)
    - `license-check.yml` — SPDX header verification + no-runtime-deps guard
    - `pattern-check.yml` — internal-pattern scan with allowlist
    - `scorecard.yml` — OpenSSF Scorecard supply-chain analysis
    - `cla.yml` — CLA Assistant Lite
    - `stale.yml` — stale issues/PRs automation
    - `release.yml` — versioned source archive attached to GitHub Releases
  - `.github/dependabot.yml` — monthly Python and GitHub Actions updates
  - README badges, tagline, and Requirements/Contributing/Security/License/Citation sections

## [0.1.0] - 2026-06-11

### Added
- `autoguardrails` harness: an autoresearch-style guardrail loop that searches
  over a single mutable `policy.md` surface against a fixed evaluation suite
- CLI subcommands `baseline`, `candidate`, `evaluate`, and `status`
- Deterministic offline stub target model and heuristic frozen judge, plus an
  OpenAI-compatible transport for real-model experiments
- Protected-surface manifest that rejects any change outside `policy.md`
- Top-line metric: attack success rate (`ASR`) with a benign-pass floor
- Fixed evaluation suite (`eval_suite.jsonl`), frozen judge prompt
  (`judge_prompt.md`), and append-only run log (`results.tsv`)
- `run_autoguardrails.sh` convenience wrapper and `tests/` regression suite

[Unreleased]: https://github.com/SantanderAI/autoguardrails/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SantanderAI/autoguardrails/releases/tag/v0.1.0
