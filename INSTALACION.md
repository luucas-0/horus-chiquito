# 🛡️ HORUS - Guía de Instalación

## 📋 Requisitos Previos

| Herramienta      | Versión mínima | ¿Para qué se usa?                              |
|------------------|----------------|-------------------------------------------------|
| **Node.js**      | v18+           | Ejecutar el backend (API Express)               |
| **npm**          | v9+            | Instalar paquetes de Node.js                    |
| **Docker**       | v20+           | Contenedores de escaneo (Kali, MySQL, etc.)     |
| **Docker Compose** | v2+          | Orquestar todos los servicios con un solo comando |
| **Git**          | cualquiera     | Clonar el repositorio                           |

---

## 🚀 Instalación Paso a Paso

### Paso 1 — Clonar el repositorio

```bash
git clone https://github.com/69kingDavid69/back-integrative-project.git
cd back-integrative-project
```

---

### Paso 2 — Instalar dependencias del Backend

```bash
cd BACKEND/api
npm install
```

Esto instalará automáticamente todos los paquetes necesarios:

| Paquete        | Función                                      |
|----------------|----------------------------------------------|
| `express`      | Framework del servidor web                   |
| `cors`         | Permitir peticiones entre dominios           |
| `dotenv`       | Cargar variables de entorno desde `.env`     |
| `mysql2`       | Conexión a la base de datos MySQL            |
| `xml2js`       | Parsear resultados XML de Nmap               |
| `ip-cidr`      | Cálculos de subredes y rangos IP             |
| `openai`       | Integración con la API de OpenAI (opcional)  |
| `pdfkit`       | Generación de reportes en PDF                |
| `nodemailer`   | Envío de reportes por correo electrónico     |
| `puppeteer`    | Renderizado avanzado para reportes           |
| `nodemon`      | Recarga automática en modo desarrollo        |

---

### Paso 3 — Configurar las Variables de Entorno

Crea un archivo `.env` dentro de `BACKEND/api/`. Puedes copiar este ejemplo y editarlo con tus datos:

```env
# ── Escaneo ──
SKIP_AUTHORIZATION=true
KALI_CONTAINER=kali-redteam
SCANNER_DOCKER_NETWORK=lab_net
ALLOW_PUBLIC_TARGETS=false
AUTHORIZED_TARGETS=192.168.1.0/24
SCAN_PROFILE=balanced

# ── Hydra (fuerza bruta) ──
HYDRA_ENABLED=true
HYDRA_MAX_ATTEMPTS=112
HYDRA_MAX_DURATION_SEC=20
HYDRA_COOLDOWN_SEC=120
HYDRA_TASKS=4
HYDRA_STOP_ON_LOCKOUT=true
HYDRA_STOP_ON_RATE_LIMIT=true

# ── Base de Datos MySQL ──
DB_ENABLED=true
DB_HOST=127.0.0.1
DB_PORT=3308
DB_USER=horus_app
DB_PASSWORD=TU_PASSWORD_AQUI
DB_NAME=horus_db

# ── OpenAI (opcional) ──
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini

# ── Email / SMTP (opcional) ──
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=tu_correo@gmail.com
SMTP_PASSWORD=tu_app_password
SMTP_FROM=tu_correo@gmail.com
```

> ⚠️ **Importante:** Nunca subas el archivo `.env` a GitHub. Ya está incluido en el `.gitignore`.

---

### Paso 4 — Levantar los servicios con Docker Compose

Desde la raíz del proyecto, ejecuta:

```bash
cd docker
docker compose up -d
```

Esto levantará automáticamente:

| Servicio          | Puerto  | Descripción                          |
|-------------------|---------|--------------------------------------|
| `scanner-api`     | `3000`  | Backend Node.js (Express)            |
| `mysql-db`        | `3308`  | Base de datos MySQL 8.0              |
| `kali-scanner`    | —       | Contenedor Kali Linux para escaneos  |
| `security-api`    | `8001`  | API FastAPI (Python) unificada       |
| `db` (PostgreSQL) | `5432`  | Base de datos auxiliar                |

---

### Paso 5 — (Alternativa) Levantar solo el Backend en modo desarrollo

Si prefieres ejecutar el backend sin Docker (por ejemplo, para desarrollo local):

```bash
cd BACKEND/api
npm run dev
```

El servidor arrancará en `http://localhost:3000`.

---

### Paso 6 — Acceder al Frontend

El frontend se sirve automáticamente desde el backend. Una vez que el servidor esté corriendo, simplemente abre en tu navegador:

```
http://localhost:3000
```

No necesitas instalar nada adicional para el frontend.

---

## ✅ Verificar que todo funciona

Abre tu navegador y visita:

```
http://localhost:3000/api/health
```

Si todo está bien, verás una respuesta como:

```json
{
  "ok": true,
  "service": "horus-backend-api",
  "timestamp": "2026-03-04T..."
}
```

---

## 📁 Estructura del Proyecto

```
HORUS/
├── BACKEND/
│   └── api/
│       ├── .env                ← Variables de entorno (NO subir a Git)
│       ├── server.js           ← Punto de entrada del servidor
│       ├── package.json        ← Dependencias de Node.js
│       ├── routes/             ← Rutas de la API
│       ├── services/           ← Lógica de negocio (escaneo, DB, IA)
│       ├── config/             ← Configuración de conexiones
│       └── utils/              ← Funciones auxiliares
├── FRONTED/
│   └── frontend/
│       ├── index.html          ← Página principal
│       ├── app.js              ← Lógica del frontend
│       └── styles.css          ← Estilos
├── docker/
│   └── docker-compose.yml      ← Orquestación de contenedores
└── docs/                       ← Documentación adicional
```
