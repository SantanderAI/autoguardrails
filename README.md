# autoguardrails

> **Open source by Santander AI Lab.** An **LLM / AI-safety** guardrail research **library / evaluation harness** (autoresearch-style): it searches over a single mutable `policy.md` surface to minimize attack success rate (ASR) against a fixed evaluation suite, with a benign-pass floor.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/SantanderAI/autoguardrails/actions/workflows/ci.yml/badge.svg)](https://github.com/SantanderAI/autoguardrails/actions/workflows/ci.yml)
[![CodeQL](https://github.com/SantanderAI/autoguardrails/actions/workflows/codeql.yml/badge.svg)](https://github.com/SantanderAI/autoguardrails/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/gh/SantanderAI/autoguardrails/branch/main/graph/badge.svg)](https://codecov.io/gh/SantanderAI/autoguardrails)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/SantanderAI/autoguardrails/badge)](https://scorecard.dev/viewer/?uri=github.com/SantanderAI/autoguardrails)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-%23FE5196.svg)](https://conventionalcommits.org)
Part of [**Santander AI Open Source**](https://github.com/SantanderAI) — open source AI projects from Banco Santander ([santander.com](https://santander.com)).

`autoguardrails` is a small alignment research scaffold inspired by Karpathy's `autoresearch`.

Instead of searching over `train.py`, this repo searches over `policy.md`.
The idea is the same:

- keep the mutable surface tiny
- keep the evaluator fixed
- run under a fixed wall-clock budget
- compare candidates with one top-line metric
- log every keep or discard decision

In this repo, the top-line metric is attack success rate (`ASR`, lower is better), with a benign-pass floor so the system cannot win by refusing everything.

## What Matters Most

For day-to-day experimentation, three files matter most:

- `program.md`: the human-owned instructions for the loop
- `policy.md`: the only file you should edit between runs
- `results.tsv`: the append-only run log

Everything else is fixed harness code or fixed evaluation data.

## Current Research Contract

- Mutable surface: `policy.md`
- Fixed suite: `eval_suite.jsonl`
- Fixed judge prompt: `judge_prompt.md`
- Fixed harness: `autoguardrails/`
- Acceptance rule: keep a candidate only if `ASR` improves and benign pass does not fall by more than 2 percentage points
- Runtime budget: fixed by the harness config, currently 5 minutes per evaluation pass

If you want a mental model closer to the original `autoresearch`, think of `autoguardrails/` as the fixed helper layer and `policy.md` as the single file under search.

## Quick Start

Run from the repository root.

1. Record a baseline.

```bash
python -m autoguardrails baseline --reset --repeat 2 --notes "initial baseline"
```

2. Edit only `policy.md`.

3. Score the new candidate.

```bash
python -m autoguardrails candidate --repeat 2 --notes "cover jailbreak and obfuscation"
```

4. Inspect the current kept result.

```bash
python -m autoguardrails status
```

5. Inspect the full log.

```bash
cat results.tsv
```

If a candidate is rejected, the harness restores `policy.md` to the last accepted version automatically.

## Shell Wrapper

If you prefer a single entrypoint, use [run_autoguardrails.sh](./run_autoguardrails.sh):

```sh
sh run_autoguardrails.sh status
sh run_autoguardrails.sh evaluate
sh run_autoguardrails.sh baseline "initial baseline" 2
sh run_autoguardrails.sh candidate "cover jailbreak and obfuscation" 2
```

On Windows, run the wrapper from Git Bash or another POSIX-compatible shell.

## Real Model Configuration

The default setup uses a deterministic local stub so the repo works offline.
To run real experiments, point the target model and the judge model at OpenAI-compatible endpoints.

Target model variables:

- `AUTOGUARDRAILS_TARGET_PROVIDER=openai_compatible`
- `AUTOGUARDRAILS_TARGET_MODEL`
- `AUTOGUARDRAILS_TARGET_API_BASE`
- `AUTOGUARDRAILS_TARGET_API_KEY`

Judge model variables:

- `AUTOGUARDRAILS_JUDGE_PROVIDER=openai_compatible`
- `AUTOGUARDRAILS_JUDGE_MODEL`
- `AUTOGUARDRAILS_JUDGE_API_BASE`
- `AUTOGUARDRAILS_JUDGE_API_KEY`

Example:

```sh
export AUTOGUARDRAILS_TARGET_PROVIDER=openai_compatible
export AUTOGUARDRAILS_TARGET_MODEL=gpt-4.1-mini
export AUTOGUARDRAILS_TARGET_API_BASE=https://your-endpoint.example/v1
export AUTOGUARDRAILS_TARGET_API_KEY=your-target-key

export AUTOGUARDRAILS_JUDGE_PROVIDER=openai_compatible
export AUTOGUARDRAILS_JUDGE_MODEL=gpt-4.1-mini
export AUTOGUARDRAILS_JUDGE_API_BASE=https://your-endpoint.example/v1
export AUTOGUARDRAILS_JUDGE_API_KEY=your-judge-key

python -m autoguardrails baseline --reset --repeat 2 --notes "real-model baseline"
```

Use a frozen judge setup during a run series. Do not switch judge prompts or judge models mid-experiment.

## Typical Iteration Pattern

A simple offline emulation cycle looks like this:

1. Record the baseline.
2. Add one policy change family to `policy.md`.
3. Run `candidate`.
4. Keep the change only if the harness accepts it.
5. Repeat with one new change at a time.

One example candidate change that improves the bundled stub is to add explicit handling for:

- jailbreak phrasing such as "ignore previous instructions", "roleplay", and "developer mode"
- obfuscation requests such as translation, base64, rot13, JSON-only formatting, or schema conversion

That gives you a realistic first improvement curve without changing the evaluator.

## Repository Layout

- `program.md`: experiment instructions and constraints
- `policy.md`: mutable guardrail policy under search
- `judge_prompt.md`: frozen judge prompt
- `eval_suite.jsonl`: fixed attack and benign eval cases
- `results.tsv`: run log
- `run_autoguardrails.sh`: convenience wrapper around the CLI
- `autoguardrails/`: fixed Python harness
- `tests/`: regression and safety checks for the harness

See [autoguardrails/README.md](./autoguardrails/README.md) for the code architecture and [tests/README.md](./tests/README.md) for the test strategy.

## Safety Notes

- This scaffold is intentionally single-turn and narrow in scope.
- It does not model tools, file access, or multi-step agent actions.
- The bundled stub is for harness verification only; it is not a realistic safety model.
- The eval suite is fixed by design. If you change it, start a new experiment lineage instead of comparing against old results.

## Requirements

- **Python 3.10+**
- **No third-party runtime dependencies** — the harness is built entirely on the Python standard library and runs offline by default.
- Optional, for development only: `ruff`, `black`, `mypy`, `pytest`, `pytest-cov` (see [CONTRIBUTING.md](CONTRIBUTING.md)).
- Optional, for real-model experiments: access to an OpenAI-compatible chat-completions endpoint (configured via the `AUTOGUARDRAILS_*` environment variables described above).

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md)
and [Code of Conduct](CODE_OF_CONDUCT.md) before getting started.

- Report bugs and request features via [GitHub Issues](https://github.com/SantanderAI/autoguardrails/issues).
- External contributors sign the CLA (handled automatically by the CLA Assistant bot on your first PR).
- Run `ruff check .`, `black --check .`, `mypy autoguardrails`, and `pytest` before opening a PR.
- Respect the research contract: `policy.md` is the only mutable surface; `eval_suite.jsonl` and `judge_prompt.md` are frozen.

## Security

Please report security vulnerabilities responsibly. See our [Security Policy](SECURITY.md)
for how to report (do **not** open a public issue for vulnerabilities). Contact:
**opensource@gruposantander.com** or use GitHub Security Advisories.

## Disclaimer

This software is an open source project from the **Santander AI Lab**, provided **"as is"** under its [license](LICENSE), without warranties or conditions of any kind. It is **not an official Banco Santander product or service**, carries no commitment of production support, and does not constitute financial, legal or professional advice.

"Santander" and its logo are registered trademarks of **Banco Santander, S.A.** The project license does not grant any right to use them beyond factual attribution.

If you believe you have found a security vulnerability, follow our [security policy](https://github.com/SantanderAI/.github/blob/main/SECURITY.md) — do not open a public issue. You are responsible for assessing the suitability of this software for your use case and for keeping your own deployments up to date.

## License

This project is licensed under the **Apache License 2.0** — see the [LICENSE](LICENSE)
and [NOTICE](NOTICE) files for details.

```
Copyright (c) 2026 Santander Group
SPDX-License-Identifier: Apache-2.0
```

## Citation

If you use `autoguardrails` in your research, please cite it:

```bibtex
@software{autoguardrails2026,
  author  = {{Santander AI Lab}},
  title   = {autoguardrails: an autoresearch-style guardrail policy loop},
  year    = {2026},
  url     = {https://github.com/SantanderAI/autoguardrails},
  license = {Apache-2.0}
}
```

