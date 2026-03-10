# HORUS Project Structure

## Overview

- `FRONTED/`
  - `FRONTED/frontend/`: main web UI served by the Node API.
- `BACKEND/`
  - `BACKEND/api/`: Node.js API and unified FastAPI service.
  - `BACKEND/database/`: SQL schema and database assets.
  - `BACKEND/ai-orchestrator/`: analysis engine, correlation, ML, scanner, and agent code.
  - `BACKEND/labs/`: vulnerable lab, validation scripts, and Kali tooling.
- `docs/`
  - `docs/es/`: Spanish documentation.
  - `docs/en/`: English documentation.

## Why this layout

- Clear separation between frontend and backend.
- AI orchestration grouped under a dedicated backend domain.
- Centralized and bilingual documentation.
