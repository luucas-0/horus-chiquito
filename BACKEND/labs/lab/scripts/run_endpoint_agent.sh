#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-${PROJECT_ROOT}/.venv/bin/python3.13}"
API_BASE="${API_BASE:-http://127.0.0.1:3000}"
WATCH_DIRS="${WATCH_DIRS:-$HOME/Desktop,$HOME/Documents,$HOME/Downloads}"
POLL_INTERVAL="${POLL_INTERVAL:-1.0}"

if [ ! -x "${PYTHON_BIN}" ]; then
  echo "Python executable not found: ${PYTHON_BIN}"
  exit 1
fi

echo "[agent] API_BASE=${API_BASE}"
echo "[agent] WATCH_DIRS=${WATCH_DIRS}"

echo "[agent] starting endpoint telemetry runner..."
PYTHONPATH="${PROJECT_ROOT}/BACKEND/ai-orchestrator" \
  "${PYTHON_BIN}" -m agent.runner \
  --api-base "${API_BASE}" \
  --directories "${WATCH_DIRS}" \
  --interval "${POLL_INTERVAL}"
