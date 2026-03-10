# QUICK START (Espanol)

## 1) Requisitos

- macOS/Linux
- Node.js 20+
- Python 3.12+ (se recomienda entorno virtual)
- Docker Desktop activo
- MySQL local o contenedor MySQL (puerto `3307` recomendado)

## 2) Estructura base

Proyecto raiz esperado:

- `/Users/user/Desktop/HORUS`
- Frontend: `/Users/user/Desktop/HORUS/FRONTED/frontend`
- Backend: `/Users/user/Desktop/HORUS/BACKEND`

## 3) Instalar dependencias Node

```bash
cd /Users/user/Desktop/HORUS/BACKEND/api
npm install
```

## 4) Configurar base de datos MySQL

Crear DB y aplicar schema:

```bash
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS horus_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -u root -p horus_db < /Users/user/Desktop/HORUS/BACKEND/database/schema.mysql.sql
```

Si usas contenedor MySQL:

```bash
docker run -d --name horus-mysql \
  -e MYSQL_ROOT_PASSWORD='RootHorus#2026' \
  -e MYSQL_DATABASE='horus_db' \
  -e MYSQL_USER='horus_app' \
  -e MYSQL_PASSWORD='HorusApp#2026' \
  -p 3307:3306 mysql:8.4
```

## 5) Configurar entorno del backend Node

Editar:

- `/Users/user/Desktop/HORUS/BACKEND/api/.env`

Minimo recomendado:

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

## 6) Levantar API Node (puerto 3000)

```bash
cd /Users/user/Desktop/HORUS/BACKEND/api
npm run dev
```

Probar health:

```bash
curl -sS http://127.0.0.1:3000/api/health
```

## 7) Levantar API unificada FastAPI (puerto 8001)

En otra terminal:

```bash
cd /Users/user/Desktop/HORUS
python3 -m venv .venv
source .venv/bin/activate
pip install -r BACKEND/api/requirements-unified.txt
python -m uvicorn BACKEND.api.main:app --host 127.0.0.1 --port 8001
```

Probar risk score:

```bash
curl -sS http://127.0.0.1:3000/api/v2/risk-score
```

## 7.1) Levantar agente endpoint anti-ransomware (recomendado)

En otra terminal:

```bash
cd /Users/user/Desktop/HORUS
bash BACKEND/labs/lab/scripts/run_endpoint_agent.sh
```

## 8) Levantar laboratorio vulnerable

```bash
cd /Users/user/Desktop/HORUS
bash BACKEND/labs/lab/scripts/lab_up.sh
```

## 9) Ejecutar validacion integral

```bash
cd /Users/user/Desktop/HORUS
bash BACKEND/labs/lab/scripts/validate_lab.sh
```

## 10) Probar frontend integrado

- Abre: `http://127.0.0.1:3000`
- Se sirve desde: `FRONTED/frontend`
- El chat IA y el monitor unificado consumen `/api/*` y `/api/v2/*`

## 11) Detener laboratorio

```bash
cd /Users/user/Desktop/HORUS
bash BACKEND/labs/lab/scripts/lab_down.sh
```

## 12) Opcion Docker Compose (todo junto)

```bash
cd /Users/user/Desktop/HORUS
docker compose up -d --build
```

## 13) Laboratorio hibrido (Hydra + Ransomware Safe)

```bash
cd /Users/user/Desktop/HORUS
bash BACKEND/labs/lab/scripts/lab_hybrid_up.sh
bash BACKEND/labs/lab/scripts/validate_hybrid_lab.sh
```

Guia completa:

- `/Users/user/Desktop/HORUS/docs/es/LAB_HIBRIDO_HYDRA_RANSOMWARE.md`

## 14) Activar OpenAI para chat generativo

```bash
cd /Users/user/Desktop/HORUS
bash BACKEND/api/scripts/set_openai_key.sh sk-tu-clave-real
```

Luego reinicia Node API y en el chat ejecuta: `estado ia`.
