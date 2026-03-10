#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
BACKEND_DIR="${PROJECT_ROOT}/BACKEND"
API_BASE="${API_BASE:-http://127.0.0.1:3000}"
TARGET_CONTAINER="${TARGET_CONTAINER:-lab-vuln-host}"

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is unavailable."
  exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -q "^${TARGET_CONTAINER}$"; then
  echo "Container ${TARGET_CONTAINER} is not running."
  echo "Start lab first: bash ${BACKEND_DIR}/labs/lab/scripts/lab_hybrid_up.sh"
  exit 1
fi

TARGET_IP="$(docker inspect -f '{{with index .NetworkSettings.Networks "lab_net"}}{{.IPAddress}}{{end}}' "${TARGET_CONTAINER}" 2>/dev/null || true)"
TARGET_IP="$(echo "${TARGET_IP}" | tr -d '[:space:]')"

if [ -z "${TARGET_IP}" ]; then
  echo "Could not resolve target IP for ${TARGET_CONTAINER} on lab_net."
  exit 1
fi

if ! curl -sS -m 6 "${API_BASE}/api/health" >/dev/null 2>&1; then
  echo "Node API is unreachable on ${API_BASE}."
  exit 1
fi

RISK_JSON="$(curl -sS -m 8 "${API_BASE}/api/v2/risk-score" || true)"
if echo "${RISK_JSON}" | grep -qi "Unified API unavailable"; then
  echo "FastAPI service is not reachable through Node proxy."
  exit 1
fi

echo "[1/4] Running network scan against ${TARGET_IP}"
SCAN_JSON="$(curl -sS -m 180 -X POST "${API_BASE}/api/simulations" \
  -H 'content-type: application/json' \
  -d "{\"target\":\"${TARGET_IP}\"}")"

python3 - <<'PY' "${SCAN_JSON}"
import json
import sys

payload = json.loads(sys.argv[1])
if payload.get("error"):
    raise SystemExit(f"Scan API error: {payload.get('error')}")

ports = [p.get("port") for p in payload.get("ports", [])]
hits = [
    c for c in payload.get("credential_tests", [])
    if c.get("status") == "credentials_found"
]

expected_ports = {21, 22, 23, 80, 445}
detected_ports = {int(p) for p in ports if str(p).isdigit()}
matched = sorted(expected_ports.intersection(detected_ports))

print("Open ports:", ports)
print("Expected vulnerable ports detected:", matched)
print("Hydra credential hits from API scan:", len(hits))
for hit in hits:
    details = hit.get("details") or {}
    print(f"  - {hit.get('service')}:{hit.get('port')} -> {details.get('user')}:{details.get('password')}")

if len(matched) < 4:
    raise SystemExit(f"Expected at least 4 vulnerable lab ports, got {matched}")
PY

echo "[1.1/4] Confirming weak credentials directly (controlled Hydra check)"
DIRECT_HYDRA_OUT="$(docker run --rm --network=lab_net kali-redteam sh -lc "hydra -l admin -p admin ${TARGET_IP} ftp -t 2 -f -I" 2>&1 || true)"
printf '%s\n' "${DIRECT_HYDRA_OUT}" | sed -n '1,20p'

if ! printf '%s' "${DIRECT_HYDRA_OUT}" | grep -qi "valid password found"; then
  echo "Direct Hydra check did not find weak credentials on ftp/admin:admin."
  echo "Adjust lab users or scan policy before remediation testing."
  exit 1
fi

echo "[2/4] Triggering ransomware-safe scenario"
bash "${BACKEND_DIR}/labs/lab/scripts/trigger_ransomware_scenario.sh"

echo "[3/4] Validating unified findings"
FINDINGS_JSON="$(curl -sS -m 15 "${API_BASE}/api/v2/findings")"
python3 - <<'PY' "${FINDINGS_JSON}"
import json
import sys

payload = json.loads(sys.argv[1])
items = payload.get("items", [])

by_type = {}
for item in items:
    key = item.get("finding_type", "unknown")
    by_type[key] = by_type.get(key, 0) + 1

mass = by_type.get("mass_encryption_detected", 0)
honey = by_type.get("honeypot_touched", 0)

print("mass_encryption_detected:", mass)
print("honeypot_touched:", honey)

if (mass + honey) <= 0:
    raise SystemExit("Expected endpoint anti-ransomware finding was not generated")
PY

echo "[4/4] Current risk score"
curl -sS -m 10 "${API_BASE}/api/v2/risk-score"
echo

echo "Hybrid lab validation completed successfully."
