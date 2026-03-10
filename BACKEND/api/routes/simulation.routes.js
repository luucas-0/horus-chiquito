import express from "express";
import { runDeepScan, discoverHosts, detectLocalNetwork } from "../services/docker.service.js";
import { validateTarget, isAuthorizedTarget, validateSubnet, isPublicTarget } from "../utils/validators.js";
import {
    canPersist,
    getSimulationById,
    getSimulationsByUser,
    persistDiscoveryResult,
    persistScanResult
} from "../services/db.service.js";
import { dispatchScanTelemetry } from "../services/telemetry.service.js";

const router = express.Router();

function parseEnvBool(value) {
    return String(value || "").trim().toLowerCase() === "true";
}

function parseUserId(value) {
    const parsed = Number.parseInt(String(value ?? ""), 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : 1;
}

function resolveUserId(req) {
    return parseUserId(
        req.headers["x-user-id"] ||
        // req.query.user_id ||
        // req.query.userId ||
        // req.body?.user_id ||
        req.body?.userId
    );
}

// GET /api/simulations/network
router.get("/network", (req, res) => {
    try {
        const networks = detectLocalNetwork();
        res.json({ networks });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// GET /api/simulations/history?user_id=1
router.get("/history", async (req, res) => {
    const userId = resolveUserId(req);

    if (!(await canPersist())) {
        return res.status(503).json({
            error: "Database unavailable",
            detail: "Persistence is not configured or cannot connect to MySQL."
        });
    }

    try {
        const items = await getSimulationsByUser(userId);
        return res.json({
            user_id: userId,
            count: items.length,
            items
        });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

// GET /api/simulations/:simulationId
router.get("/:simulationId", async (req, res) => {
    const simulationId = Number.parseInt(req.params.simulationId, 10);
    if (!Number.isFinite(simulationId) || simulationId <= 0) {
        return res.status(400).json({ error: "simulationId must be a positive integer" });
    }

    if (!(await canPersist())) {
        return res.status(503).json({
            error: "Database unavailable",
            detail: "Persistence is not configured or cannot connect to MySQL."
        });
    }

    try {
        const simulation = await getSimulationById(simulationId);
        if (!simulation) {
            return res.status(404).json({ error: "Simulation not found" });
        }

        return res.json(simulation);
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

// POST /api/simulations/discover
router.post("/discover", async (req, res) => {
    const { subnet } = req.body;

    if (!subnet || !validateSubnet(subnet)) {
        return res.status(400).json({ error: "Invalid subnet. Use CIDR format, e.g. 192.168.1.0/24" });
    }

    const cidrPrefix = Number.parseInt(subnet.split("/")[1], 10);
    if (cidrPrefix < 20) {
        return res.status(400).json({
            error: `La subred /${cidrPrefix} es demasiado grande (${Math.pow(2, 32 - cidrPrefix).toLocaleString()} IPs). Usa /20 o mas pequeña (ej: /24 = 254 IPs). Usa el boton 'Auto-detectar' para obtener tu subred correcta.`
        });
    }

    try {
        const result = await discoverHosts(subnet);
        const userId = resolveUserId(req);
        let simulationId = null;
        let persistenceWarning = null;

        if (await canPersist()) {
            try {
                simulationId = await persistDiscoveryResult(result, { userId });
            } catch (persistenceError) {
                persistenceWarning = `Discovery persisted failed: ${persistenceError.message}`;
                console.warn("[DISCOVERY PERSISTENCE WARNING]", persistenceWarning);
            }
        } else {
            persistenceWarning = "Persistence disabled/unavailable. Result returned without DB save.";
        }

        return res.json({
            ...result,
            simulation_id: simulationId,
            ...(persistenceWarning ? { persistence_warning: persistenceWarning } : {})
        });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

// POST /api/simulations
router.post("/", async (req, res) => {
    const { target } = req.body;

    if (!validateTarget(target)) {
        return res.status(400).json({ error: "Invalid target IP" });
    }

    const skipAuth = parseEnvBool(process.env.SKIP_AUTHORIZATION);
    const allowPublicTargets = parseEnvBool(process.env.ALLOW_PUBLIC_TARGETS);

    if (isPublicTarget(target) && !allowPublicTargets) {
        return res.status(403).json({
            error: "Public WAN targets are disabled. Set ALLOW_PUBLIC_TARGETS=true and authorize target in AUTHORIZED_TARGETS."
        });
    }

    if (!skipAuth && !isAuthorizedTarget(target)) {
        return res.status(403).json({
            error: "Target not authorized. Add it to AUTHORIZED_TARGETS (CIDR or exact IP)."
        });
    }

    try {
        const result = await runDeepScan(target);
        const userId = resolveUserId(req);
        let simulationId = null;
        let persistenceWarning = null;

        if (await canPersist()) {
            try {
                const persisted = await persistScanResult(result, { userId, scanType: "deep_scan" });
                simulationId = persisted.simulationId;
            } catch (persistenceError) {
                persistenceWarning = `Scan persisted failed: ${persistenceError.message}`;
                console.warn("[SCAN PERSISTENCE WARNING]", persistenceWarning);
            }
        } else {
            persistenceWarning = "Persistence disabled/unavailable. Result returned without DB save.";
        }

        // Auto-dispatch behavioral telemetry to the unified anti-ransomware engine.
        // Runs asynchronously — never blocks the scan response.
        dispatchScanTelemetry(result).catch(err =>
            console.warn("[TELEMETRY] Background dispatch error:", err.message)
        );

        return res.json({
            ...result,
            simulation_id: simulationId,
            ...(persistenceWarning ? { persistence_warning: persistenceWarning } : {})
        });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

export default router;
