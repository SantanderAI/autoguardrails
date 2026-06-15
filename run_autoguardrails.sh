#!/usr/bin/env sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON_BIN="${PYTHON_BIN:-python}"
DEFAULT_REPEAT="${AUTOGUARDRAILS_REPEAT:-2}"

usage() {
  cat <<'EOF'
Usage:
  ./run_autoguardrails.sh status
  ./run_autoguardrails.sh evaluate [repeat]
  ./run_autoguardrails.sh baseline [notes] [repeat]
  ./run_autoguardrails.sh reset-baseline [notes] [repeat]
  ./run_autoguardrails.sh candidate [notes] [repeat]
  ./run_autoguardrails.sh raw <autoguardrails args...>

Examples:
  ./run_autoguardrails.sh status
  ./run_autoguardrails.sh evaluate
  ./run_autoguardrails.sh baseline "initial baseline" 2
  ./run_autoguardrails.sh candidate "cover jailbreak and obfuscation" 2
  ./run_autoguardrails.sh raw evaluate --repeat 3

Environment overrides:
  PYTHON_BIN=python3
  AUTOGUARDRAILS_REPEAT=2
EOF
}

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python executable not found: $PYTHON_BIN" >&2
  exit 1
fi

cd "$SCRIPT_DIR"

command_name="${1:-}"

if [ -z "$command_name" ]; then
  usage
  exit 1
fi

shift

case "$command_name" in
  status)
    exec "$PYTHON_BIN" -m autoguardrails status
    ;;
  evaluate)
    repeat="${1:-$DEFAULT_REPEAT}"
    exec "$PYTHON_BIN" -m autoguardrails evaluate --repeat "$repeat"
    ;;
  baseline)
    notes="${1:-initial baseline}"
    repeat="${2:-$DEFAULT_REPEAT}"
    exec "$PYTHON_BIN" -m autoguardrails baseline --repeat "$repeat" --notes "$notes"
    ;;
  reset-baseline)
    notes="${1:-initial baseline}"
    repeat="${2:-$DEFAULT_REPEAT}"
    exec "$PYTHON_BIN" -m autoguardrails baseline --reset --repeat "$repeat" --notes "$notes"
    ;;
  candidate)
    notes="${1:-candidate iteration}"
    repeat="${2:-$DEFAULT_REPEAT}"
    exec "$PYTHON_BIN" -m autoguardrails candidate --repeat "$repeat" --notes "$notes"
    ;;
  raw)
    if [ "$#" -eq 0 ]; then
      echo "raw expects arguments for python -m autoguardrails" >&2
      exit 1
    fi
    exec "$PYTHON_BIN" -m autoguardrails "$@"
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    echo "Unknown command: $command_name" >&2
    usage >&2
    exit 1
    ;;
esac

