#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
BACKEND_DIR="${PROJECT_ROOT}/BACKEND"
LAB_COMPOSE_FILE="${BACKEND_DIR}/labs/lab/docker-compose.lab.yml"

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is unavailable."
  echo "Open Docker Desktop and wait until the engine is running."
  exit 1
fi

docker compose -f "${LAB_COMPOSE_FILE}" up -d --build

TARGET_IP="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' lab-vuln-host)"
ATTACKER_IP="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' lab-ransom-attacker)"

# Seed data, backups, and honeypot marker for anti-ransomware tests.
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
Vulnerable lab started.
Victim container: lab-vuln-host (${TARGET_IP})
Attacker container: lab-ransom-attacker (${ATTACKER_IP})
Docker network: lab_net (172.28.10.0/24)
Exposed vulnerable ports: 21(ftp), 22(ssh), 23(telnet), 80(http), 445(smb)

Next step (BACKEND/api/.env):
  SCANNER_DOCKER_NETWORK=lab_net
  AUTHORIZED_TARGETS=172.28.10.0/24

Suggested flow:
  1) Deep scan victim:
     curl -sS -X POST http://127.0.0.1:3000/api/simulations -H 'content-type: application/json' -d '{"target":"${TARGET_IP}"}'

  2) Trigger ransomware-safe scenario:
     bash ${BACKEND_DIR}/labs/lab/scripts/trigger_ransomware_scenario.sh

  3) Validate findings:
     bash ${BACKEND_DIR}/labs/lab/scripts/validate_hybrid_lab.sh

Then restart the Node API:
  cd ${BACKEND_DIR}/api && npm run dev
EOT
