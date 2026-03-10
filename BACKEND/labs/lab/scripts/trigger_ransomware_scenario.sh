#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-http://127.0.0.1:3000}"
ATTACKER_CONTAINER="${ATTACKER_CONTAINER:-lab-ransom-attacker}"
VICTIM_CONTAINER="${VICTIM_CONTAINER:-lab-vuln-host}"
EVENT_COUNT="${EVENT_COUNT:-50}"

if ! docker ps --format '{{.Names}}' | grep -q "^${ATTACKER_CONTAINER}$"; then
  echo "Attacker container ${ATTACKER_CONTAINER} is not running."
  exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -q "^${VICTIM_CONTAINER}$"; then
  echo "Victim container ${VICTIM_CONTAINER} is not running."
  exit 1
fi

echo "[1/4] Executing safe ransomware-like activity over shared volumes ..."
docker exec "${ATTACKER_CONTAINER}" sh -lc '
  mkdir -p /srv/labdata/ransom_batch /srv/backups

  # Encrypt-like churn: high-entropy files with .locked extension.
  for i in $(seq -w 1 90); do
    head -c 3072 /dev/urandom > "/srv/labdata/ransom_batch/archivo_${i}.locked"
  done

  # Backup tampering simulation (non-destructive marker rewrite).
  for f in /srv/backups/*.bak; do
    [ -f "${f}" ] || continue
    cp "${f}" "${f}.encrypted"
    printf "\\nRANSOMWARE_SIMULATION_MARKER\\n" >> "${f}.encrypted"
  done

  # Honeypot file touch.
  if [ -f /srv/labdata/.horus_honeypot ]; then
    mv /srv/labdata/.horus_honeypot /srv/labdata/.horus_honeypot.touched
  fi
'

echo "[2/4] Sending endpoint telemetry events to anti-ransomware engine ..."
for i in $(seq 1 "${EVENT_COUNT}"); do
  event_path="/srv/labdata/ransom_batch/archivo_${i}.locked"
  payload="$(cat <<JSON
{
  "action": "modified",
  "path": "${event_path}",
  "extension_after": ".locked",
  "entropy_before": 2.0,
  "entropy_after": 7.95,
  "process_is_signed": false,
  "process_has_network_access": true,
  "process_spawned_by_suspicious": true,
  "process_age_seconds": 20,
  "api_crypto_calls": 180,
  "honeypot_touched": true,
  "honeypot_modified": true,
  "vss_delete_attempt": true,
  "backup_path_access": true
}
JSON
)"

  curl -sS -m 5 -X POST "${API_BASE}/api/v2/agent/event" \
    -H 'content-type: application/json' \
    -d "${payload}" >/dev/null
done

echo "[3/4] Fetching risk-score ..."
curl -sS -m 10 "${API_BASE}/api/v2/risk-score"
echo

echo "[4/4] Quick endpoint findings summary ..."
findings="$(curl -sS -m 10 "${API_BASE}/api/v2/findings")"
python3 - <<'PY' "${findings}"
import json
import sys

payload = json.loads(sys.argv[1])
items = payload.get("items", [])
by_type = {}
for item in items:
    ftype = item.get("finding_type", "unknown")
    by_type[ftype] = by_type.get(ftype, 0) + 1

for key in ("mass_encryption_detected", "honeypot_touched", "weak_credentials"):
    print(f"{key}: {by_type.get(key, 0)}")
PY
