# Tests README

This directory contains the regression tests for the fixed harness.

The tests are meant to protect the experiment contract, not just the code paths.

## Run The Tests

```bash
python -m unittest discover -s tests -v
```

## What The Tests Cover

- `test_eval_runner.py`
  - validates the shape of `eval_suite.jsonl`
  - checks that repeated offline stub evaluations are stable

- `test_loop.py`
  - verifies that a policy improvement can be accepted
  - verifies that edits outside `policy.md` are rejected by the protected-surface check

## When To Update Tests

Update the tests when you intentionally change one of these:

- eval suite size or schema
- acceptance logic
- repeatability expectations
- protected-surface rules

If you only edit `policy.md`, you should not need to touch this directory.

## Testing Philosophy

The point of the suite is to prevent accidental drift in the fixed harness.
That means the tests should stay small, deterministic, and easy to understand.

