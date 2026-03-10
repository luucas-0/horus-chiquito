/**
 * telemetry.service.js
 *
 * Converts Nmap + Hydra deep-scan results into behavioral telemetry events
 * and sends them automatically to the unified anti-ransomware engine
 * (POST /api/v2/agent/event via UNIFIED_API_BASE).
 *
 * Works for ANY target IP — lab containers, internal hosts, or external machines.
 * The "behavioral telemetry" is derived from what an attacker *could* do
 * given the discovered vulnerabilities (threat modeling from scan results).
 */

const UNIFIED_API_BASE = (process.env.UNIFIED_API_BASE || "http://127.0.0.1:8001").replace(/\/$/, "");

/**
 * Risk signals derived from open ports and services.
 * Each entry maps a port number to the behavioral indicators
 * that a threat actor exploiting that service would trigger.
 */
const PORT_RISK_SIGNALS = {
    "21": { backup_path_access: true, process_has_network_access: true, api_crypto_calls: 30 },
    "22": { process_has_network_access: true, process_spawned_by_suspicious: true, process_age_seconds: 20 },
    "23": { process_has_network_access: true, process_spawned_by_suspicious: true, process_age_seconds: 15 },
    "80": { process_has_network_access: true },
    "443": { process_has_network_access: true },
    "445": { backup_path_access: true, process_has_network_access: true, api_crypto_calls: 60 },
    "3389": { process_has_network_access: true, process_spawned_by_suspicious: true },
    "3306": { backup_path_access: true, process_has_network_access: true },
    "5432": { backup_path_access: true, process_has_network_access: true },
    "1433": { backup_path_access: true, process_has_network_access: true },
};

/**
 * Extra signals applied when Hydra finds valid credentials on a service.
 * Successful credential access dramatically increases the risk footprint.
 */
const CREDENTIAL_COMPROMISE_SIGNALS = {
    action: "modified",
    extension_after: ".locked",
    entropy_before: 2.1,
    entropy_after: 7.9,
    process_is_signed: false,
    process_has_network_access: true,
    process_spawned_by_suspicious: true,
    process_age_seconds: 20,
    api_crypto_calls: 140,
    honeypot_touched: true,
    honeypot_modified: true,
    vss_delete_attempt: true,
    backup_path_access: true,
};

/**
 * Send a single event payload to the FastAPI unified engine.
 * Errors are silenced so a failing FastAPI never breaks the scan response.
 */
async function sendEvent(event) {
    try {
        const res = await fetch(`${UNIFIED_API_BASE}/api/v2/agent/event`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(event),
            signal: AbortSignal.timeout(5000),
        });
        if (!res.ok) {
            console.warn(`[TELEMETRY] Event rejected by unified engine: ${res.status}`);
        }
    } catch (err) {
        // FastAPI may not be running — degrade gracefully.
        console.warn(`[TELEMETRY] Could not reach unified engine: ${err.message}`);
    }
}

/**
 * Derive and send behavioral telemetry events from a completed deep-scan result.
 *
 * Strategy:
 *  1. One baseline "reconnaissance" event per open port, encoding the risk
 *     signals that exploitation of that service would introduce.
 *  2. One "credential-compromise" burst (N events) for each service where
 *     Hydra found valid credentials — simulating what a ransomware actor
 *     would do once they gain authenticated access.
 *
 * @param {object} scanResult  - Return value of docker.service.js#runDeepScan()
 */
export async function dispatchScanTelemetry(scanResult) {
    const openPorts = scanResult?.ports ?? [];
    const credentialTests = scanResult?.credential_tests ?? [];
    const host = scanResult?.host ?? "unknown";
    const events = [];

    // ── 1. One event per open port ────────────────────────────────────────────
    for (const portInfo of openPorts) {
        const portStr = String(portInfo.port);
        const signals = PORT_RISK_SIGNALS[portStr] ?? { process_has_network_access: true };

        events.push({
            action: "network_probe",
            path: `/net/${host}/${portInfo.service ?? portStr}`,
            ...signals,
        });
    }

    // ── 2. Credential-compromise burst for each cracked service ──────────────
    const compromisedServices = credentialTests.filter(t => t.status === "credentials_found");

    for (const svc of compromisedServices) {
        // Send multiple events to reflect sustained attacker activity
        const burstSize = 15;
        for (let i = 1; i <= burstSize; i++) {
            events.push({
                ...CREDENTIAL_COMPROMISE_SIGNALS,
                path: `/net/${host}/${svc.service}/ransom_${String(i).padStart(2, "0")}.locked`,
            });
        }
    }

    // ── 3. Telnet open = high-risk plain-text protocol ────────────────────────
    const telnetOpen = openPorts.some(p => String(p.port) === "23");
    if (telnetOpen) {
        events.push({
            action: "suspicious_process",
            path: `/net/${host}/telnet_session`,
            process_has_network_access: true,
            process_spawned_by_suspicious: true,
            process_is_signed: false,
            process_age_seconds: 10,
        });
    }

    if (events.length === 0) {
        console.log(`[TELEMETRY] No telemetry events to dispatch for ${host}.`);
        return;
    }

    console.log(`[TELEMETRY] Dispatching ${events.length} events for ${host} -> ${UNIFIED_API_BASE}`);

    // Send all events concurrently (fire-and-forget, non-blocking)
    await Promise.allSettled(events.map(sendEvent));

    console.log(`[TELEMETRY] Done dispatching telemetry for ${host}.`);
}
