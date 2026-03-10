#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-http://127.0.0.1:3000}"
TARGET_CONTAINER="${TARGET_CONTAINER:-lab-vuln-host}"
EVENT_COUNT="${EVENT_COUNT:-40}"

if ! docker ps --format '{{.Names}}' | grep -q "^${TARGET_CONTAINER}$"; then
  echo "Contenedor ${TARGET_CONTAINER} no esta corriendo."
  exit 1
fi

echo "[1/3] Simulando modificaciones masivas seguras en /srv/labdata ..."
docker exec "${TARGET_CONTAINER}" sh -lc '
  mkdir -p /srv/labdata/ransom_test
  for i in $(seq -w 1 80); do
    head -c 2048 /dev/urandom > "/srv/labdata/ransom_test/archivo_${i}.locked"
  done
'

echo "[2/3] Enviando telemetria anti-ransomware al backend ..."
for i in $(seq 1 "${EVENT_COUNT}"); do
  curl -sS -m 5 -X POST "${API_BASE}/api/v2/agent/event" \
    -H 'content-type: application/json' \
    -d '{
      "action": "modified",
      "path": "/srv/labdata/ransom_test/archivo_'"${i}"'.locked",
      "extension_after": ".locked",
      "entropy_before": 2.1,
      "entropy_after": 7.9,
      "process_is_signed": false,
      "process_has_network_access": true,
      "process_spawned_by_suspicious": true,
      "process_age_seconds": 30,
      "api_crypto_calls": 140,
      "honeypot_touched": true,
      "honeypot_modified": true,
      "vss_delete_attempt": true,
      "backup_path_access": true
    }' >/dev/null
done

echo "[3/3] Estado actual de riesgo unificado:"
curl -sS -m 10 "${API_BASE}/api/v2/risk-score"
echo
