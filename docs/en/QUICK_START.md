# QUICK START (English)

## 1) Requirements

- macOS/Linux
- Node.js 20+
- Python 3.12+ (virtualenv recommended)
- Docker Desktop running
- Local MySQL or MySQL container (`3307` recommended)

## 2) Expected layout

Project root:

- `/Users/user/Desktop/HORUS`
- Frontend: `/Users/user/Desktop/HORUS/FRONTED/frontend`
- Backend: `/Users/user/Desktop/HORUS/BACKEND`

## 3) Install Node dependencies

```bash
cd /Users/user/Desktop/HORUS/BACKEND/api
npm install
```

## 4) Configure MySQL database

Create DB and apply schema:

```bash
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS horus_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -u root -p horus_db < /Users/user/Desktop/HORUS/BACKEND/database/schema.mysql.sql
```

If using MySQL container:

```bash
docker run -d --name horus-mysql \
  -e MYSQL_ROOT_PASSWORD='RootHorus#2026' \
  -e MYSQL_DATABASE='horus_db' \
  -e MYSQL_USER='horus_app' \
  -e MYSQL_PASSWORD='HorusApp#2026' \
  -p 3307:3306 mysql:8.4
```

## 5) Configure Node backend environment

Edit:

- `/Users/user/Desktop/HORUS/BACKEND/api/.env`

Minimum recommended values:

```env
UNIFIED_API_BASE=http://127.0.0.1:8001
DB_ENABLED=true
DB_HOST=127.0.0.1
DB_PORT=3307
DB_USER=horus_app
DB_PASSWORD=HorusApp#2026
DB_NAME=horus_db
OPENAI_API_KEY=
```

## 6) Start Node API (port 3000)

```bash
cd /Users/user/Desktop/HORUS/BACKEND/api
npm run dev
```

Health check:

```bash
curl -sS http://127.0.0.1:3000/api/health
```

## 7) Start unified FastAPI service (port 8001)

In another terminal:

```bash
cd /Users/user/Desktop/HORUS
python3 -m venv .venv
source .venv/bin/activate
pip install -r BACKEND/api/requirements-unified.txt
python -m uvicorn BACKEND.api.main:app --host 127.0.0.1 --port 8001
```

Risk score check:

```bash
curl -sS http://127.0.0.1:3000/api/v2/risk-score
```

## 7.1) Start endpoint anti-ransomware agent (recommended)

In another terminal:

```bash
cd /Users/user/Desktop/HORUS
bash BACKEND/labs/lab/scripts/run_endpoint_agent.sh
```

## 8) Start vulnerable lab

```bash
cd /Users/user/Desktop/HORUS
bash BACKEND/labs/lab/scripts/lab_up.sh
```

## 9) Run integrated validation

```bash
cd /Users/user/Desktop/HORUS
bash BACKEND/labs/lab/scripts/validate_lab.sh
```

## 10) Test integrated frontend

- Open: `http://127.0.0.1:3000`
- Served from: `FRONTED/frontend`
- AI chat and unified monitor consume `/api/*` and `/api/v2/*`

## 11) Stop lab

```bash
cd /Users/user/Desktop/HORUS
bash BACKEND/labs/lab/scripts/lab_down.sh
```

## 12) Docker Compose option (all services)

```bash
cd /Users/user/Desktop/HORUS
docker compose up -d --build
```

## 13) Hybrid Lab (Hydra + Ransomware Safe)

```bash
cd /Users/user/Desktop/HORUS
bash BACKEND/labs/lab/scripts/lab_hybrid_up.sh
bash BACKEND/labs/lab/scripts/validate_hybrid_lab.sh
```

Full guide:

- `/Users/user/Desktop/HORUS/docs/es/LAB_HIBRIDO_HYDRA_RANSOMWARE.md`

## 14) Enable OpenAI for generative chat

```bash
cd /Users/user/Desktop/HORUS
bash BACKEND/api/scripts/set_openai_key.sh sk-your-real-key
```

Then restart Node API and run `estado ia` in chat.
