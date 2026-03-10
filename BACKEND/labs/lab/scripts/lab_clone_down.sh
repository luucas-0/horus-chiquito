#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
BACKEND_DIR="${PROJECT_ROOT}/BACKEND"
CLONE_COMPOSE_FILE="${BACKEND_DIR}/labs/lab/docker-compose.clone-lab.yml"

docker compose -f "${CLONE_COMPOSE_FILE}" down -v --remove-orphans

echo "Clone lab stopped and volumes removed."
