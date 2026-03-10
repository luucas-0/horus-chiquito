#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ENV_FILE="${PROJECT_ROOT}/BACKEND/api/.env"

if [ ! -f "${ENV_FILE}" ]; then
  echo "No se encontro .env en ${ENV_FILE}"
  exit 1
fi

OPENAI_KEY="${1:-}"
if [ -z "${OPENAI_KEY}" ]; then
  read -r -s -p "Ingresa OPENAI_API_KEY: " OPENAI_KEY
  echo
fi

if [ -z "${OPENAI_KEY}" ]; then
  echo "OPENAI_API_KEY vacia. Cancelado."
  exit 1
fi

if ! printf '%s' "${OPENAI_KEY}" | rg -q '^sk-'; then
  echo "Advertencia: la clave no parece tener formato sk-..."
fi

if rg -q '^OPENAI_API_KEY=' "${ENV_FILE}"; then
  perl -0pi -e 's/^OPENAI_API_KEY=.*/OPENAI_API_KEY='"${OPENAI_KEY//\//\\/}"'/m' "${ENV_FILE}"
else
  printf '\nOPENAI_API_KEY=%s\n' "${OPENAI_KEY}" >> "${ENV_FILE}"
fi

echo "OPENAI_API_KEY actualizada en ${ENV_FILE}"
echo "Reinicia Node API para aplicar cambios:"
echo "  cd ${PROJECT_ROOT}/BACKEND/api && npm run dev"
