# Harness README

This directory contains the fixed Python harness for the `autoguardrails` experiment loop.

The research idea is that you do not modify this package during ordinary iterations.
You modify `policy.md`, and this package scores, compares, and logs the result.

## Module Map

- `__main__.py`: CLI entrypoint for `baseline`, `candidate`, `evaluate`, and `status`
- `config.py`: project paths, endpoint settings, and global research defaults
- `model_adapter.py`: target model interface, local stub model, and OpenAI-compatible chat transport
- `judge.py`: frozen judge implementations and judge-output parsing
- `eval_runner.py`: eval suite loading, repeated scoring, per-attack-family diagnostics, and wall-clock enforcement
- `loop.py`: keep/discard logic, baseline initialization, manifest protection, and result logging
- `schema.py`: shared dataclasses for eval cases and run summaries

## How The Pieces Fit Together

1. `__main__.py` loads the project paths and endpoint configuration.
2. `model_adapter.py` builds the target model used to answer eval prompts.
3. `judge.py` builds the frozen judge that scores those answers.
4. `eval_runner.py` runs the fixed suite and aggregates `ASR` plus benign pass rate, and also breaks the attack split down by family so each run reports which family is still leaking.
5. `loop.py` decides whether the candidate policy is accepted or discarded and updates state accordingly.

## Fixed vs Mutable

During normal experiments:

- mutable: repository-root `policy.md`
- fixed: everything in this package

That boundary is enforced by the protected manifest stored under `.autoguardrails/`.
If any fixed file changes between baseline and candidate evaluation, the run fails.

## Important Defaults

- wall-clock budget: `900` seconds per evaluation pass
- benign tolerance: `0.02`
- tie tolerance: `0.005`
- default offline provider: `stub`
- deterministic decoding: `temperature=0`, `top_p=1`

These are implementation defaults, not theoretical requirements.
If you later choose to change them, treat that as a harness revision, not a routine policy iteration.

## CLI Commands

```bash
python -m autoguardrails baseline --reset --repeat 2 --notes "initial baseline"
python -m autoguardrails candidate --repeat 2 --notes "candidate iteration"
python -m autoguardrails evaluate --repeat 2
python -m autoguardrails status
```

## Extension Guidance

If you want to evolve the repo without breaking the experiment contract, good extension points are:

- adding a new transport in `model_adapter.py`
- replacing the heuristic stub judge with a stronger frozen judge
- expanding the eval suite with a new versioned benchmark
- adding richer reporting around `results.tsv`

Avoid changing the harness and the policy at the same time if you want comparable results.

