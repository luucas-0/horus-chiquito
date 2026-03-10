#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
BACKEND_DIR="${PROJECT_ROOT}/BACKEND"
LAB_COMPOSE_FILE="${BACKEND_DIR}/labs/lab/docker-compose.lab.yml"

docker compose -f "${LAB_COMPOSE_FILE}" down -v --remove-orphans
echo "Lab stopped and volumes removed."
