#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
BACKEND_DIR="${PROJECT_ROOT}/BACKEND"
BASE_COMPOSE_FILE="${BACKEND_DIR}/labs/lab/docker-compose.lab.yml"
HYBRID_COMPOSE_FILE="${BACKEND_DIR}/labs/lab/docker-compose.hybrid-lab.yml"

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is unavailable."
  echo "Open Docker Desktop and wait until the engine is running."
  exit 1
fi

# Avoid name/IP collisions if the legacy lab is up.
docker compose -f "${BASE_COMPOSE_FILE}" down --remove-orphans >/dev/null 2>&1 || true

# Start hybrid lab with weak credentials + shared data surface.
docker compose -f "${HYBRID_COMPOSE_FILE}" up -d --build

TARGET_IP="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' lab-vuln-host)"
ATTACKER_IP="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' lab-ransom-attacker)"

# Seed data, backups, and a honeypot marker in shared volumes.
docker exec lab-vuln-host sh -lc '
  mkdir -p /srv/labdata/finance /srv/labdata/legal /srv/backups
  for i in $(seq -w 1 30); do
    echo "Factura de prueba ${i}" > "/srv/labdata/finance/factura_${i}.txt"
  done
  for i in $(seq -w 1 10); do
    echo "Backup baseline ${i}" > "/srv/backups/snapshot_${i}.bak"
  done
  echo "DO_NOT_TOUCH_HONEYPOT" > /srv/labdata/.horus_honeypot
  chmod -R 0777 /srv/labdata /srv/backups
'

cat <<EOT
Hybrid lab started.
Victim container: lab-vuln-host (${TARGET_IP})
Attacker container: lab-ransom-attacker (${ATTACKER_IP})
Docker network: lab_net (172.28.10.0/24)
Exposed vulnerable ports: 21(ftp), 22(ssh), 23(telnet), 80(http), 445(smb)

Recommended BACKEND/api/.env values:
  SCANNER_DOCKER_NETWORK=lab_net
  AUTHORIZED_TARGETS=172.28.10.0/24

Suggested flow:
  1) Scan for Hydra findings:
     curl -sS -X POST http://127.0.0.1:3000/api/simulations -H 'content-type: application/json' -d '{"target":"${TARGET_IP}"}'

  2) Trigger ransomware-safe scenario:
     bash ${BACKEND_DIR}/labs/lab/scripts/trigger_ransomware_scenario.sh

  3) Validate findings/risk:
     bash ${BACKEND_DIR}/labs/lab/scripts/validate_hybrid_lab.sh
EOT
