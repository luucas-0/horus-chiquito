#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
API_DIR="${PROJECT_ROOT}/BACKEND/api"
ENV_FILE="${API_DIR}/.env"

API_BASE="${API_BASE:-http://127.0.0.1:3000}"
UNIFIED_BASE="${UNIFIED_BASE:-http://127.0.0.1:8001}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-horus2026}"

red() { printf '\033[31m%s\033[0m\n' "$1"; }
green() { printf '\033[32m%s\033[0m\n' "$1"; }
yellow() { printf '\033[33m%s\033[0m\n' "$1"; }

fail() {
  red "[FAIL] $1"
  exit 1
}

ok() {
  green "[OK] $1"
}

info() {
  printf '[INFO] %s\n' "$1"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

read_env_value() {
  local key="$1"
  local file="$2"
  if [ ! -f "$file" ]; then
    return 1
  fi
  local line
  line="$(grep -E "^${key}=" "$file" | tail -n 1 || true)"
  if [ -z "$line" ]; then
    return 1
  fi
  echo "${line#*=}" | tr -d '"' | tr -d "'"
}

check_port() {
  local port="$1"
  nc -z 127.0.0.1 "$port" >/dev/null 2>&1
}

require_cmd curl
require_cmd nc
require_cmd python3

if [ ! -f "$ENV_FILE" ]; then
  fail "Env file not found: $ENV_FILE"
fi

DB_HOST="$(read_env_value DB_HOST "$ENV_FILE" || echo '127.0.0.1')"
DB_PORT="$(read_env_value DB_PORT "$ENV_FILE" || echo '3306')"

info "Configured DB host/port: ${DB_HOST}:${DB_PORT}"

if [ "$DB_HOST" != "127.0.0.1" ] && [ "$DB_HOST" != "localhost" ]; then
  yellow "DB_HOST=${DB_HOST}. This smoke test only probes local TCP ports."
else
  if check_port "$DB_PORT"; then
    ok "Configured DB port ${DB_PORT} is reachable"
  else
    red "Configured DB port ${DB_PORT} is NOT reachable"
    reachable_ports=()
    for p in 3306 3307 3308; do
      if check_port "$p"; then
        reachable_ports+=("$p")
      fi
    done

    if [ "${#reachable_ports[@]}" -gt 0 ]; then
      yellow "Reachable local MySQL ports: ${reachable_ports[*]}"
      yellow "Update ${ENV_FILE} -> DB_PORT=${reachable_ports[0]} if that is your active MySQL instance."
    else
      yellow "No local MySQL ports detected on 3306/3307/3308. Start MySQL before login tests."
    fi

    fail "Database port mismatch (this is the root cause of ECONNREFUSED on login)."
  fi
fi

info "Checking Node API health at ${API_BASE}/api/health"
NODE_HEALTH="$(curl -sS -m 6 "${API_BASE}/api/health" || true)"
if [ -z "$NODE_HEALTH" ]; then
  fail "Node API unreachable on ${API_BASE}. Start: cd ${API_DIR} && npm run dev"
fi

python3 - <<'PY' "$NODE_HEALTH"
import json
import sys
payload = json.loads(sys.argv[1])
if not payload.get("ok"):
    raise SystemExit("Node health returned ok=false")
print("Node health service:", payload.get("service"))
PY
ok "Node API health endpoint responds"

info "Checking FastAPI direct endpoint at ${UNIFIED_BASE}/api/v2/risk-score"
DIRECT_RISK="$(curl -sS -m 8 "${UNIFIED_BASE}/api/v2/risk-score" || true)"
if [ -z "$DIRECT_RISK" ]; then
  fail "FastAPI unreachable on ${UNIFIED_BASE}. Start: cd ${PROJECT_ROOT} && source .venv/bin/activate && python -m uvicorn BACKEND.api.main:app --host 127.0.0.1 --port 8001"
fi

python3 - <<'PY' "$DIRECT_RISK"
import json
import sys
payload = json.loads(sys.argv[1])
if "risk" not in payload:
    raise SystemExit("FastAPI risk-score payload does not contain 'risk'")
print("FastAPI risk score:", payload.get("risk"))
PY
ok "FastAPI direct endpoint responds"

info "Checking FastAPI through Node proxy at ${API_BASE}/api/v2/risk-score"
PROXY_RISK="$(curl -sS -m 8 "${API_BASE}/api/v2/risk-score" || true)"
if echo "$PROXY_RISK" | grep -qi "Unified API unavailable"; then
  fail "Node proxy cannot reach FastAPI (UNIFIED_API_BASE)"
fi

python3 - <<'PY' "$PROXY_RISK"
import json
import sys
payload = json.loads(sys.argv[1])
if "risk" not in payload:
    raise SystemExit("Proxy risk-score payload does not contain 'risk'")
print("Proxy risk score:", payload.get("risk"))
PY
ok "Node proxy -> FastAPI is working"

info "Testing admin login at ${API_BASE}/api/auth/login"
LOGIN_PAYLOAD=$(printf '{"username":"%s","password":"%s"}' "$ADMIN_USERNAME" "$ADMIN_PASSWORD")
LOGIN_RESPONSE="$(curl -sS -m 8 -X POST "${API_BASE}/api/auth/login" -H 'content-type: application/json' -d "$LOGIN_PAYLOAD" || true)"

if [ -z "$LOGIN_RESPONSE" ]; then
  fail "Login endpoint did not respond"
fi

python3 - <<'PY' "$LOGIN_RESPONSE"
import json
import sys
payload = json.loads(sys.argv[1])
if not (payload.get("ok") is True or payload.get("success") is True):
    err = payload.get("error") or payload.get("message") or str(payload)
    raise SystemExit(f"Login failed: {err}")
user = payload.get("user") or {}
print("Logged in as:", user.get("username") or user.get("email") or "unknown")
PY
ok "Admin login succeeded"

green "Smoke test completed successfully."
