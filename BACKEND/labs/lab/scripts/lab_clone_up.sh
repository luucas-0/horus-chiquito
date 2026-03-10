#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
BACKEND_DIR="${PROJECT_ROOT}/BACKEND"
CLONE_COMPOSE_FILE="${BACKEND_DIR}/labs/lab/docker-compose.clone-lab.yml"

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is unavailable."
  echo "Open Docker Desktop and wait until the engine is running."
  exit 1
fi

docker compose -f "${CLONE_COMPOSE_FILE}" up -d --build

TARGET_IP="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' lab-vuln-host-clone)"
ATTACKER_IP="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' lab-ransom-attacker-clone)"

# Seed data, backups, and honeypot marker for anti-ransomware tests.
docker exec lab-vuln-host-clone sh -lc '
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
Clone lab started.
Victim container: lab-vuln-host-clone (${TARGET_IP})
Attacker container: lab-ransom-attacker-clone (${ATTACKER_IP})
Docker network: lab_net (172.28.10.0/24)
Exposed vulnerable ports: 21(ftp), 22(ssh), 23(telnet), 80(http), 445(smb)

Use this new target IP in UI deep scan:
  ${TARGET_IP}

Suggested flow:
  1) Deep scan clone victim:
     curl -sS -X POST http://127.0.0.1:3000/api/simulations -H 'content-type: application/json' -d '{"target":"${TARGET_IP}"}'

  2) Trigger ransomware-safe scenario on clone lab:
     ATTACKER_CONTAINER=lab-ransom-attacker-clone VICTIM_CONTAINER=lab-vuln-host-clone \
       bash ${BACKEND_DIR}/labs/lab/scripts/trigger_ransomware_scenario.sh

  3) Validate unified findings on clone target:
     TARGET_CONTAINER=lab-vuln-host-clone bash ${BACKEND_DIR}/labs/lab/scripts/validate_hybrid_lab.sh
EOT
