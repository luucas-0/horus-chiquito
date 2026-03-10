import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const envPath = path.join(__dirname, "..", ".env");

dotenv.config({ path: envPath });

const DB_ENABLED = String(process.env.DB_ENABLED ?? "true").trim().toLowerCase() !== "false";

let poolPromise = null;

function parsePort(rawPort) {
    const parsed = Number.parseInt(rawPort ?? "3306", 10);
    return Number.isFinite(parsed) ? parsed : 3306;
}

function buildDbConfig() {
    return {
        host: process.env.DB_HOST || "127.0.0.1",
        port: parsePort(process.env.DB_PORT),
        user: process.env.DB_USER || "root",
        password: process.env.DB_PASSWORD || "",
        database: process.env.DB_NAME || "horus_db",
        waitForConnections: true,
        connectionLimit: Number.parseInt(process.env.DB_CONNECTION_LIMIT || "10", 10) || 10,
        queueLimit: 0,
        timezone: "+00:00"
    };
}

async function loadMysqlDriver() {
    try {
        const mysqlModule = await import("mysql2/promise");
        return mysqlModule.default;
    } catch (error) {
        throw new Error(
            "mysql2 no esta instalado. Ejecuta `npm install` dentro de /BACKEND/api para habilitar persistencia."
        );
    }
}

export function isDbEnabled() {
    return DB_ENABLED;
}

export async function getDbPool() {
    if (!DB_ENABLED) {
        throw new Error("Database persistence is disabled (DB_ENABLED=false)");
    }

    if (!poolPromise) {
        poolPromise = (async () => {
            const mysql = await loadMysqlDriver();
            const pool = mysql.createPool(buildDbConfig());
            return pool;
        })();
    }

    return poolPromise;
}

export async function execute(query, params = []) {
    const pool = await getDbPool();
    return pool.execute(query, params);
}

export async function testDbConnection() {
    if (!DB_ENABLED) {
        return false;
    }

    const pool = await getDbPool();
    const connection = await pool.getConnection();
    connection.release();
    return true;
}
