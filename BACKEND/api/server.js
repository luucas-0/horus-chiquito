import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import simulationRoutes from "./routes/simulation.routes.js";
import aiRoutes from "./routes/ai.routes.js";
import authRoutes from "./routes/auth.routes.js";
import adminRoutes from "./routes/admin.routes.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const envPath = path.join(__dirname, ".env");

// Load environment variables from BACKEND/api/.env regardless of launch cwd.
dotenv.config({ path: envPath });

const app = express();

app.use(cors());
app.use(express.json({ limit: "2mb" }));

const unifiedApiBase = process.env.UNIFIED_API_BASE || "http://127.0.0.1:8001";

// Proxy /api/v2 to FastAPI unified backend.
app.use("/api/v2", async (req, res) => {
    try {
        const upstreamUrl = new URL(req.originalUrl, unifiedApiBase);
        const headers = {};

        if (req.headers["content-type"]) {
            headers["content-type"] = req.headers["content-type"];
        }

        const isBodyMethod = !["GET", "HEAD"].includes(req.method);
        const body = isBodyMethod ? JSON.stringify(req.body || {}) : undefined;

        const upstreamResponse = await fetch(upstreamUrl, {
            method: req.method,
            headers,
            body
        });

        const contentType = upstreamResponse.headers.get("content-type") || "";
        const textPayload = await upstreamResponse.text();

        res.status(upstreamResponse.status);
        if (contentType) {
            res.set("content-type", contentType);
        }

        if (contentType.includes("application/json")) {
            try {
                return res.json(JSON.parse(textPayload));
            } catch {
                return res.json({ raw: textPayload });
            }
        }

        return res.send(textPayload);
    } catch (error) {
        return res.status(502).json({
            error: "Unified API unavailable. Start FastAPI service on port 8001.",
            detail: error.message
        });
    }
});

// API routes
app.use("/api/auth", authRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/simulations", simulationRoutes);
app.use("/api/ai", aiRoutes);

// Simple health endpoint
app.get("/api/health", (req, res) => {
    res.json({
        ok: true,
        service: "horus-backend-api",
        timestamp: new Date().toISOString()
    });
});

// Static frontend
const frontendDirectory = path.join(__dirname, "../../FRONTED/frontend");
app.use(express.static(frontendDirectory));

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
