import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const envPath = path.join(__dirname, "..", ".env");

dotenv.config({ path: envPath });

function parseIntEnv(name, fallback) {
    const parsed = Number.parseInt(process.env[name] ?? "", 10);
    return Number.isFinite(parsed) ? parsed : fallback;
}

function parseBooleanEnv(name, fallback = false) {
    const value = String(process.env[name] ?? "").trim().toLowerCase();

    if (!value) {
        return fallback;
    }

    if (["1", "true", "yes", "on"].includes(value)) {
        return true;
    }

    if (["0", "false", "no", "off"].includes(value)) {
        return false;
    }

    return fallback;
}

export function getMailConfig() {
    const port = parseIntEnv("SMTP_PORT", 587);
    const secure = parseBooleanEnv("SMTP_SECURE", port === 465);

    return {
        host: String(process.env.SMTP_HOST || "").trim(),
        port,
        secure,
        user: String(process.env.SMTP_USER || "").trim(),
        password: String(process.env.SMTP_PASSWORD || "").trim(),
        from: String(process.env.SMTP_FROM || "").trim(),
        allowInsecureTLS: parseBooleanEnv("SMTP_ALLOW_INSECURE_TLS", false)
    };
}

export function isMailConfigured() {
    const config = getMailConfig();
    return Boolean(config.host && config.from);
}
