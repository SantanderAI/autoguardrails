# Contributing to autoguardrails

Thanks for your interest in contributing! This project is a small alignment
research scaffold: a stdlib-only Python harness (`autoguardrails/`) that searches
over a single mutable `policy.md` surface against a fixed evaluation suite.
Contributions of all kinds are welcome: bug reports, documentation, harness
improvements, and additional benign/attack eval cases.

By participating, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to contribute

- **Report a bug** — open a [bug report issue](.github/ISSUE_TEMPLATE/bug_report.yml).
- **Request a feature** — open a [feature request issue](.github/ISSUE_TEMPLATE/feature_request.yml).
- **Submit a change** — follow the fork-based pull request flow below.
- **Report a vulnerability** — see [SECURITY.md](SECURITY.md) (do **not** open a public issue).

## The research contract (read before changing the harness)

`autoguardrails` only works as a comparison tool if the evaluation surface stays
fixed between runs. Please respect these boundaries:

- `policy.md` is the **only** file expected to change between baseline and candidate runs.
- `eval_suite.jsonl` and `judge_prompt.md` are **frozen**. If you change them, you
  start a new experiment lineage — say so explicitly in your PR, and do not compare
  the new numbers against old `results.tsv` rows.
- The harness enforces this with a protected-surface manifest; PRs that loosen that
  guarantee need an explicit rationale.

## Pull Request Process

### For External Contributors

1. **Fork** the repository to your GitHub account.
2. **Create a branch** from `main` with a descriptive name:
   ```bash
   git checkout -b feature/add-attack-family
   ```
3. **Make your changes** following the [Code Style](#code-style) guidelines.
4. **Add tests** for any new functionality.
5. **Update documentation** if your changes affect the CLI or the research contract.
6. **Commit** with clear messages following [Conventional Commits](https://www.conventionalcommits.org/):
   ```
   feat: add a cyber attack family to the stub classifier
   fix: restore policy.md when a candidate is rejected
   docs: clarify the benign-pass floor
   ```
7. **Push** your branch and open a Pull Request against `main`.
8. **Sign the CLA** when prompted by the CLA Assistant bot.
9. **Wait for review** — a maintainer will review your PR within 2 weeks (SLA).

### For Internal Contributors (Santander)

1. **Create a branch** from `main` (no fork needed if you are a member of the org).
2. Follow steps 3-7 above.
3. Request review from the maintainer team in [CODEOWNERS](CODEOWNERS).

### PR Requirements

All pull requests must pass the following automated checks before merge:

- [ ] **CI lint and tests** (`ci`) — Linting, formatting, type-check, unit tests
- [ ] **Security scan** (`codeql`, `dep-scan`) — SAST and dependency audit
- [ ] **License check** (`license-check`) — SPDX headers + no runtime-dependency creep
- [ ] **Pattern check** (`pattern-check`) — No internal URLs, IPs, or corporate email addresses
- [ ] **CLA signed** (for external contributors)

Additionally:

- At least **1 maintainer approval** is required.
- All review conversations must be resolved.
- The branch must be up to date with `main`.

## Code Style

### Python

- Follow [PEP 8](https://peps.python.org/pep-0008/).
- Use [Black](https://black.readthedocs.io/) for formatting (line length: 100).
- Use [Ruff](https://docs.astral.sh/ruff/) for linting.
- Use [mypy](https://mypy-lang.org/) for type checking.
- All public functions and classes must have docstrings (Google style).
- Keep the harness **dependency-free** (Python standard library only).

### File Headers

Every source file must include the copyright header:

```python
# Copyright (c) 2026 Santander Group
# SPDX-License-Identifier: Apache-2.0
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Use |
|:---|:---|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `docs:` | Documentation only |
| `test:` | Adding or updating tests |
| `refactor:` | Code refactoring (no feature/fix) |
| `ci:` | CI/CD changes |
| `chore:` | Maintenance tasks |

## Testing

- Write tests for all new functionality.
- Use [pytest](https://docs.pytest.org/) as the test framework.
- Place tests in the `tests/` directory, mirroring the source structure.
- Run the full test suite before submitting a PR:
  ```bash
  pytest tests/ -v --cov=autoguardrails
  ```
- Minimum code coverage target: **80%**.

## Contributor License Agreement (CLA)

By submitting a pull request, you agree to the terms of our Contributor License
Agreement. The [CLA Assistant](https://cla-assistant.io/) bot will automatically
check your PR and ask you to sign the CLA if you have not already done so.

The CLA ensures that contributions can be distributed under the project's Apache 2.0 license.

## Release Process

This project follows [Semantic Versioning (SemVer)](https://semver.org/):

- **MAJOR** — Incompatible API changes
- **MINOR** — New features (backward-compatible)
- **PATCH** — Bug fixes (backward-compatible)

Releases are managed by maintainers. If you believe a release is warranted, open an issue to discuss.

---

Thank you for contributing to **autoguardrails**!
