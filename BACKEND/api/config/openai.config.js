import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const envPath = path.join(__dirname, "..", ".env");

dotenv.config({ path: envPath });

function parseFloatEnv(name, fallback) {
    const parsed = Number.parseFloat(process.env[name] ?? "");
    return Number.isFinite(parsed) ? parsed : fallback;
}

function parseIntEnv(name, fallback) {
    const parsed = Number.parseInt(process.env[name] ?? "", 10);
    return Number.isFinite(parsed) ? parsed : fallback;
}

export function getOpenAIConfig() {
    return {
        model: process.env.OPENAI_MODEL || "gpt-4o-mini",
        temperature: parseFloatEnv("OPENAI_TEMPERATURE", 0.2),
        maxTokens: parseIntEnv("OPENAI_MAX_TOKENS", 1800)
    };
}

export function isOpenAIConfigured() {
    const apiKey = process.env.OPENAI_API_KEY;
    return Boolean(apiKey && apiKey.trim() && !apiKey.includes("your-api-key"));
}

let openaiClientPromise = null;

export async function getOpenAIClient() {
    if (!isOpenAIConfigured()) {
        throw new Error("OpenAI is not configured. Set OPENAI_API_KEY in BACKEND/api/.env");
    }

    if (!openaiClientPromise) {
        openaiClientPromise = (async () => {
            let OpenAI;

            try {
                const openaiModule = await import("openai");
                OpenAI = openaiModule.default;
            } catch {
                throw new Error("openai package is missing. Run npm install in /BACKEND/api.");
            }

            return new OpenAI({
                apiKey: process.env.OPENAI_API_KEY
            });
        })();
    }

    return openaiClientPromise;
}
