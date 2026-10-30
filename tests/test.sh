#!/bin/bash
set -uo pipefail

VERIFIER_LOG_DIR="${AEGIS_VERIFIER_LOG_DIR:-/logs/verifier}"
WORKSPACE_DIR="${AEGIS_WORKSPACE:-/workspace}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "${VERIFIER_LOG_DIR}"

# Default fail-safe reward (0.000) in case of unhandled crash or syntax error
printf "0.000\n" > "${VERIFIER_LOG_DIR}/reward.txt"
printf '{"reward": 0.0}\n' > "${VERIFIER_LOG_DIR}/reward.json"

python3 "${SCRIPT_DIR}/run_evaluation.py" \
    --workspace "${WORKSPACE_DIR}" \
    --reward-dir "${VERIFIER_LOG_DIR}"

exit 0
