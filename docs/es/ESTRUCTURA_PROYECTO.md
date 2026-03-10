# Estructura del Proyecto HORUS

## Vista general

- `FRONTED/`
  - `FRONTED/frontend/`: interfaz web principal servida por Node.
- `BACKEND/`
  - `BACKEND/api/`: API Node.js y servicio FastAPI unificado.
  - `BACKEND/database/`: scripts y esquema SQL.
  - `BACKEND/ai-orchestrator/`: motor de analisis, correlacion, ML, scanner y agente.
  - `BACKEND/labs/`: laboratorio vulnerable, scripts de pruebas y herramientas Kali.
- `docs/`
  - `docs/es/`: documentacion en espanol.
  - `docs/en/`: documentation in English.

## Objetivo de esta organizacion

- Separar claramente frontend y backend.
- Encapsular componentes de IA/orquestacion en un dominio propio.
- Mantener la documentacion centralizada y bilingue.
