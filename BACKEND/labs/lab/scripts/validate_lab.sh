#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
BACKEND_DIR="${PROJECT_ROOT}/BACKEND"
API_BASE="${API_BASE:-http://127.0.0.1:3000}"
TARGET_IP="${TARGET_IP:-}"

is_valid_ipv4() {
  local ip="$1"
  [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r o1 o2 o3 o4 <<<"${ip}"
  for octet in "${o1}" "${o2}" "${o3}" "${o4}"; do
    ((octet >= 0 && octet <= 255)) || return 1
  done
  return 0
}

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is unavailable."
  echo "Open Docker Desktop and run: bash BACKEND/labs/lab/scripts/lab_up.sh"
  exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -q '^lab-vuln-host$'; then
  echo "Container lab-vuln-host is not running."
  echo "Run first: bash BACKEND/labs/lab/scripts/lab_up.sh"
  exit 1
fi

TARGET_IP="$(echo "${TARGET_IP}" | tr -d '[:space:]')"

if [ -n "${TARGET_IP}" ] && ! is_valid_ipv4 "${TARGET_IP}"; then
  echo "Invalid TARGET_IP in environment (${TARGET_IP}). Autodetection will be used."
  TARGET_IP=""
fi

if [ -z "${TARGET_IP}" ]; then
  TARGET_IP="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' lab-vuln-host 2>/dev/null || true)"
  TARGET_IP="$(echo "${TARGET_IP}" | tr -d '[:space:]')"
fi

if [ -z "${TARGET_IP}" ]; then
  echo "TARGET_IP could not be resolved."
  echo "Check container network: docker inspect lab-vuln-host"
  exit 1
fi

if ! is_valid_ipv4 "${TARGET_IP}"; then
  echo "Invalid TARGET_IP: ${TARGET_IP}"
  echo "Set a valid IP or restart lab:"
  echo "  unset TARGET_IP"
  echo "  bash ${BACKEND_DIR}/labs/lab/scripts/lab_up.sh"
  exit 1
fi

if ! curl -sS -m 5 "${API_BASE}/" >/dev/null 2>&1; then
  echo "Node API is not reachable on ${API_BASE}."
  echo "Start Node backend in another terminal:"
  echo "  cd ${BACKEND_DIR}/api && npm run dev"
  exit 1
fi

V2_HEALTH="$(curl -sS -m 8 "${API_BASE}/api/v2/risk-score" 2>/dev/null || true)"
if echo "${V2_HEALTH}" | grep -qi "Unified API unavailable"; then
  echo "API v2 is unavailable (FastAPI on 8001 is down)."
  echo "Start FastAPI in another terminal:"
  echo "  cd ${PROJECT_ROOT} && ./.venv/bin/python -m uvicorn BACKEND.api.main:app --host 127.0.0.1 --port 8001"
  exit 1
fi

echo "[1/5] Running deep scan against ${TARGET_IP}"
SCAN_JSON="$(curl -sS -m 180 -X POST "${API_BASE}/api/simulations" \
  -H 'content-type: application/json' \
  -d "{\"target\":\"${TARGET_IP}\"}")"

python3 -c '
import json, sys
data = json.loads(sys.stdin.read())
if data.get("error"):
    print("Scan API error:", data.get("error"))
    sys.exit(1)
ports = [str(p.get("port")) for p in data.get("ports", [])]
hydra = data.get("credential_tests", [])
hits = [h for h in hydra if h.get("status") == "credentials_found"]
print("Detected ports:", ", ".join(ports) if ports else "none")
print("Hydra findings:", len(hits))
for h in hits:
    d = h.get("details") or {}
    print("  - {}:{} -> {}:{}".format(h.get("service"), h.get("port"), d.get("user"), d.get("password")))
' <<<"${SCAN_JSON}"

echo "[2/5] Simulating ransomware-like behavior"
"${BACKEND_DIR}/labs/lab/scripts/simulate_ransomware_safe.sh"

echo "[3/5] Fetching unified findings"
FINDINGS_JSON="$(curl -sS -m 20 "${API_BASE}/api/v2/findings")"
python3 -c '
import json, sys
data = json.loads(sys.stdin.read())
items = data.get("items", [])
print("Total findings:", data.get("count", len(items)))
for item in items[:8]:
    finding_id = str(item.get("id") or "")
    print("  - {} {} {} {}/100".format(finding_id[:8], item.get("source"), item.get("finding_type"), item.get("risk_score")))
' <<<"${FINDINGS_JSON}"

echo "[4/5] Preview + remediation for multi-port findings"
for FINDING_TYPE in open_critical_ports weak_credentials telnet_open; do
  FINDING_ID="$(python3 -c '
import json, sys
finding_type = sys.argv[1]
data = json.loads(sys.stdin.read())
for item in data.get("items", []):
    if item.get("finding_type") == finding_type:
        print(item.get("id"))
        break
' "${FINDING_TYPE}" <<<"${FINDINGS_JSON}")"

  if [ -n "${FINDING_ID}" ]; then
    echo "Preview (${FINDING_TYPE}):"
    curl -sS -m 20 "${API_BASE}/api/v2/remediation/preview/${FINDING_ID}"
    echo
    echo "Remediate (${FINDING_TYPE}):"
    curl -sS -m 20 -X POST "${API_BASE}/api/v2/remediate/${FINDING_ID}" \
      -H 'content-type: application/json' \
      -d '{"os_name":"linux","force":true}'
    echo
  else
    echo "No ${FINDING_TYPE} finding found in this run."
  fi
done

echo "[5/5] Final risk score"
curl -sS -m 20 "${API_BASE}/api/v2/risk-score"
echo
