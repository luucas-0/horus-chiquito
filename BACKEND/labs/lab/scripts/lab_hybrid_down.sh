#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
BACKEND_DIR="${PROJECT_ROOT}/BACKEND"
HYBRID_COMPOSE_FILE="${BACKEND_DIR}/labs/lab/docker-compose.hybrid-lab.yml"

docker compose -f "${HYBRID_COMPOSE_FILE}" down -v --remove-orphans

echo "Hybrid lab stopped and volumes removed."
