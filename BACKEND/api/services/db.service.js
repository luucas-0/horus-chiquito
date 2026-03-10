import { execute, isDbEnabled, testDbConnection } from "../config/db.js";

const DEFAULT_SYSTEM_USER_ID = Number.parseInt(process.env.DEFAULT_SYSTEM_USER_ID || "1", 10) || 1;
const tableExistsCache = new Map();

function parseInteger(value, fallback = null) {
    const parsed = Number.parseInt(String(value ?? ""), 10);
    return Number.isFinite(parsed) ? parsed : fallback;
}

function parseScanTimeSeconds(scanTimeValue) {
    if (scanTimeValue == null || scanTimeValue === "") {
        return null;
    }

    const numeric = Number.parseFloat(String(scanTimeValue));
    if (!Number.isFinite(numeric)) {
        return null;
    }

    return Math.max(0, Math.round(numeric));
}

function safeJsonParse(value, fallback = null) {
    if (value == null) {
        return fallback;
    }

    if (typeof value === "object") {
        return value;
    }

    try {
        return JSON.parse(value);
    } catch {
        return fallback;
    }
}

function buildSeveritySummary(vulnerabilities = []) {
    const summary = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
    };

    for (const vulnerability of vulnerabilities) {
        const severity = String(vulnerability?.severity || "").toLowerCase();
        if (severity in summary) {
            summary[severity] += 1;
        }
    }

    return summary;
}

function normalizeRiskTo100(riskValue) {
    const parsed = Number.parseFloat(String(riskValue ?? "0"));
    if (!Number.isFinite(parsed)) {
        return 0;
    }

    if (parsed <= 10) {
        return Math.max(0, Math.min(100, Math.round(parsed * 10)));
    }

    return Math.max(0, Math.min(100, Math.round(parsed)));
}

function buildRecommendationsText(analysis) {
    if (Array.isArray(analysis?.immediate_actions) && analysis.immediate_actions.length > 0) {
        return analysis.immediate_actions.join("\n");
    }

    if (Array.isArray(analysis?.recommendations) && analysis.recommendations.length > 0) {
        return analysis.recommendations
            .map((item) => {
                if (typeof item === "string") {
                    return item;
                }

                if (item && typeof item === "object") {
                    if (item.title && item.description) {
                        return `${item.title}: ${item.description}`;
                    }
                    return item.title || item.description || "";
                }

                return "";
            })
            .filter(Boolean)
            .join("\n");
    }

    return null;
}

function normalizeAiPayload(analysis) {
    const vulnerabilities = Array.isArray(analysis?.vulnerabilities) ? analysis.vulnerabilities : [];

    return {
        modelVersion:
            // analysis?.model_version ||
            // analysis?._mer_metadata?.ai_analysis_storage?.ai_analysis?.model_version ||
            // process.env.OPENAI_MODEL ||
            "gpt-4o-mini",
        riskScoreGlobal: normalizeRiskTo100(
            analysis?.overall_risk_score ?? analysis?.risk_score_global ?? analysis?.risk_score
        ),
        severitySummary: buildSeveritySummary(vulnerabilities),
        findings: analysis,
        recommendations: buildRecommendationsText(analysis)
    };
}

async function hasTable(tableName) {
    if (!isDbEnabled()) {
        return false;
    }

    if (tableExistsCache.has(tableName)) {
        return tableExistsCache.get(tableName);
    }

    const [rows] = await execute(
        `SELECT 1 AS exists_flag
         FROM information_schema.tables
         WHERE table_schema = DATABASE()
           AND table_name = ?
         LIMIT 1`,
        [tableName]
    );

    const exists = Array.isArray(rows) && rows.length > 0;
    tableExistsCache.set(tableName, exists);
    return exists;
}

async function ensureSystemUser(userId = DEFAULT_SYSTEM_USER_ID) {
    if (!(await hasTable("Users"))) {
        return userId;
    }

    const safeUserId = parseInteger(userId, DEFAULT_SYSTEM_USER_ID);

    await execute(
        `INSERT INTO Users (id, email, password_hash, is_active)
         VALUES (?, ?, ?, 1)
         ON DUPLICATE KEY UPDATE id = id`,
        [safeUserId, `system+${safeUserId}@horus.local`, "local-only"]
    );

    return safeUserId;
}

async function getEffectiveUserId(userId) {
    const requestedUserId = parseInteger(userId, DEFAULT_SYSTEM_USER_ID);
    return ensureSystemUser(requestedUserId);
}

export function isPersistenceEnabled() {
    return isDbEnabled();
}

export async function canPersist() {
    if (!isDbEnabled()) {
        return false;
    }

    try {
        await testDbConnection();
        return true;
    } catch {
        return false;
    }
}

export async function createSimulation({ userId, scanType, targetIp, targetSubnet = null }) {
    const effectiveUserId = await getEffectiveUserId(userId);

    const [result] = await execute(
        `INSERT INTO Simulations (user_id, scan_type, target_ip, target_subnet, status, start_time)
         VALUES (?, ?, ?, ?, 'running', NOW())`,
        [effectiveUserId, scanType, targetIp, targetSubnet]
    );

    return result.insertId;
}

export async function completeSimulation(
    simulationId,
    { status, nmapVersion, nmapCommand, scanTimeSeconds, jsonResponse, errorMessage = null }
) {
    await execute(
        `UPDATE Simulations
         SET status = ?,
             end_time = NOW(),
             scan_time_seconds = ?,
             nmap_version = ?,
             nmap_command = ?,
             json_response = ?,
             error_message = ?
         WHERE id = ?`,
        [
            status,
            scanTimeSeconds,
            nmapVersion || null,
            nmapCommand || null,
            JSON.stringify(jsonResponse ?? {}),
            errorMessage,
            simulationId
        ]
    );
}

export async function getSimulationsByUser(userId) {
    const effectiveUserId = await getEffectiveUserId(userId);

    const [rows] = await execute(
        `SELECT id,
                scan_type,
                target_ip,
                target_subnet,
                status,
                start_time,
                end_time,
                scan_time_seconds,
                nmap_version,
                nmap_command,
                error_message,
                created_at
         FROM Simulations
         WHERE user_id = ?
         ORDER BY created_at DESC
         LIMIT 100`,
        [effectiveUserId]
    );

    return rows;
}

export async function getSimulationById(simulationId) {
    const simulationNumericId = parseInteger(simulationId, null);
    if (!simulationNumericId) {
        return null;
    }

    const [[simulation]] = await execute(`SELECT * FROM Simulations WHERE id = ? LIMIT 1`, [simulationNumericId]);

    if (!simulation) {
        return null;
    }

    const parsedJsonResponse = safeJsonParse(simulation.json_response, {});
    simulation.json_response = parsedJsonResponse;

    const hosts = [];
    if (await hasTable("Hosts")) {
        const [hostRows] = await execute(
            `SELECT * FROM Hosts WHERE simulation_id = ? ORDER BY discovered_at ASC`,
            [simulationNumericId]
        );

        for (const host of hostRows) {
            if (await hasTable("Ports")) {
                const [ports] = await execute(
                    `SELECT * FROM Ports WHERE host_id = ? ORDER BY port_number ASC`,
                    [host.id]
                );
                host.ports = ports;
            } else {
                host.ports = [];
            }

            if (await hasTable("Vulnerabilities")) {
                const [vulnerabilities] = await execute(
                    `SELECT * FROM Vulnerabilities WHERE host_id = ? ORDER BY detected_at ASC`,
                    [host.id]
                );
                host.vulnerabilities = vulnerabilities;
            } else {
                host.vulnerabilities = [];
            }

            if (await hasTable("CredentialTests")) {
                const [credentialTests] = await execute(
                    `SELECT id,
                            simulation_id,
                            host_id,
                            port_id,
                            service,
                            status,
                            found_username,
                            risk_score,
                            created_at
                     FROM CredentialTests
                     WHERE host_id = ?
                     ORDER BY created_at ASC`,
                    [host.id]
                );
                host.credential_tests = credentialTests;
            } else {
                host.credential_tests = [];
            }

            hosts.push(host);
        }
    }

    let aiAnalysis = null;
    if (await hasTable("AIAnalysisResults")) {
        const [[analysisRow]] = await execute(
            `SELECT * FROM AIAnalysisResults WHERE simulation_id = ? LIMIT 1`,
            [simulationNumericId]
        );

        if (analysisRow) {
            aiAnalysis = {
                ...analysisRow,
                severity_summary: safeJsonParse(analysisRow.severity_summary, {}),
                findings: safeJsonParse(analysisRow.findings, analysisRow.findings)
            };
        }
    }

    if (!aiAnalysis) {
        aiAnalysis = parsedJsonResponse?.ai_analysis || null;
    }

    let reports = [];
    if (await hasTable("Reports")) {
        const [reportRows] = await execute(
            `SELECT * FROM Reports WHERE simulation_id = ? ORDER BY version DESC`,
            [simulationNumericId]
        );
        reports = reportRows;
    }

    return {
        ...simulation,
        hosts,
        ai_analysis: aiAnalysis,
        reports
    };
}

export async function upsertHost(
    simulationId,
    userId,
    { ipAddress, macAddress = null, macVendor = null, hostname = null, osDetection = null, deviceType = null }
) {
    const effectiveUserId = await getEffectiveUserId(userId);

    await execute(
        `INSERT IGNORE INTO Hosts
            (simulation_id, user_id, ip_address, mac_address, mac_vendor, hostname, os_detection, device_type)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [
            simulationId,
            effectiveUserId,
            ipAddress,
            macAddress,
            macVendor,
            hostname,
            osDetection,
            deviceType
        ]
    );

    const [[row]] = await execute(
        `SELECT id FROM Hosts WHERE simulation_id = ? AND ip_address = ? LIMIT 1`,
        [simulationId, ipAddress]
    );

    return row?.id || null;
}

export async function insertPorts(hostId, ports) {
    if (!Array.isArray(ports) || ports.length === 0) {
        return;
    }

    for (const port of ports) {
        const portNumber = parseInteger(port?.port ?? port?.port_number, null);
        if (portNumber == null) continue;
        await execute(
            `INSERT IGNORE INTO Ports
                (host_id, port_number, protocol, state, service, product, version, cpe, extra_info)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                hostId,
                portNumber,
                port?.protocol || "tcp",
                port?.state || "open",
                port?.service || null,
                port?.product || null,
                port?.version || null,
                port?.cpe || null,
                port?.extra_info || null
            ]
        );
    }
}

export async function getPortId(hostId, portNumber, protocol = "tcp") {
    const [[row]] = await execute(
        `SELECT id FROM Ports WHERE host_id = ? AND port_number = ? AND protocol = ? LIMIT 1`,
        [hostId, parseInteger(portNumber, 0), protocol]
    );

    return row?.id || null;
}

export async function insertVulnerabilities(simulationId, hostId, vulnerabilities) {
    if (!Array.isArray(vulnerabilities) || vulnerabilities.length === 0) {
        return;
    }

    for (const vulnerability of vulnerabilities) {
        let portId = null;
        if (vulnerability?.port_number) {
            portId = await getPortId(hostId, vulnerability.port_number, vulnerability.protocol || "tcp");
        }

        await execute(
            `INSERT INTO Vulnerabilities
                (simulation_id, host_id, port_id, script_id, severity, output)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [
                simulationId,
                hostId,
                portId,
                vulnerability?.script_id || "unknown",
                String(vulnerability?.severity || "low").toLowerCase(),
                vulnerability?.output || null
            ]
        );
    }
}

export async function insertCredentialTests(simulationId, hostId, credentialTests, userId) {
    if (!Array.isArray(credentialTests) || credentialTests.length === 0) {
        return;
    }

    const effectiveUserId = await getEffectiveUserId(userId);

    for (const credentialTest of credentialTests) {
        const portNumber = credentialTest?.port != null ? parseInteger(credentialTest.port, null) : null;
        const portId = portNumber != null ? await getPortId(hostId, portNumber, "tcp") : null;

        if (!portId) {
            continue;
        }

        const foundUser = credentialTest?.details?.user ?? credentialTest?.found_username ?? null;
        const foundPassRaw = credentialTest?.details?.password ?? credentialTest?.found_password ?? null;
        const foundPasswordNumeric = foundPassRaw != null && Number.isFinite(Number(foundPassRaw)) ? Number(foundPassRaw) : null;
        const riskScore = parseInteger(credentialTest?.risk_score, null);

        await execute(
            `INSERT INTO CredentialTests
                (simulation_id, host_id, port_id, user_id, service, status, found_username, found_password, risk_score)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                simulationId,
                hostId,
                portId,
                effectiveUserId,
                credentialTest?.service || "unknown",
                credentialTest?.status || "no_credentials_found",
                foundUser != null ? String(foundUser) : null,
                foundPasswordNumeric,
                riskScore
            ]
        );
    }
}

export async function saveAIAnalysis(simulationId, analysis, { userId = DEFAULT_SYSTEM_USER_ID } = {}) {
    const normalized = normalizeAiPayload(analysis);
    const simulationNumericId = parseInteger(simulationId, null);
    if (!simulationNumericId) {
        throw new Error("simulationId must be a positive integer");
    }

    if (await hasTable("AIAnalysisResults")) {
        await execute(
            `INSERT INTO AIAnalysisResults
                (simulation_id, model_version, risk_score_global, severity_summary, findings, recommendations)
             VALUES (?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
                model_version = VALUES(model_version),
                risk_score_global = VALUES(risk_score_global),
                severity_summary = VALUES(severity_summary),
                findings = VALUES(findings),
                recommendations = VALUES(recommendations),
                analyzed_at = NOW()`,
            [
                simulationNumericId,
                normalized.modelVersion,
                normalized.riskScoreGlobal,
                JSON.stringify(normalized.severitySummary),
                JSON.stringify(normalized.findings),
                normalized.recommendations
            ]
        );
    } else {
        const [[row]] = await execute(
            `SELECT json_response FROM Simulations WHERE id = ? LIMIT 1`,
            [simulationNumericId]
        );

        const currentJson = safeJsonParse(row?.json_response, {});
        const mergedJson = {
            ...currentJson,
            ai_analysis: normalized.findings,
            ai_analysis_meta: {
                model_version: normalized.modelVersion,
                risk_score_global: normalized.riskScoreGlobal,
                severity_summary: normalized.severitySummary,
                stored_at: new Date().toISOString()
            }
        };

        await execute(
            `UPDATE Simulations SET json_response = ? WHERE id = ?`,
            [JSON.stringify(mergedJson), simulationNumericId]
        );
    }

    await logAudit(
        userId,
        "ai_analysis_saved",
        "Simulations",
        simulationNumericId,
        {
            model_version: normalized.modelVersion,
            risk_score_global: normalized.riskScoreGlobal
        }
    );

    return normalized;
}

export async function createReport(simulationId, userId, { filename, path, sizeBytes }) {
    const effectiveUserId = await getEffectiveUserId(userId);

    const [[versionRow]] = await execute(
        `SELECT COALESCE(MAX(version), 0) + 1 AS next_version FROM Reports WHERE simulation_id = ?`,
        [simulationId]
    );

    const nextVersion = versionRow?.next_version || 1;

    const [result] = await execute(
        `INSERT INTO Reports (simulation_id, user_id, filename, path, size_bytes, version)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [simulationId, effectiveUserId, filename, path, sizeBytes ?? null, nextVersion]
    );

    return {
        id: result.insertId,
        version: nextVersion
    };
}

export async function logAudit(userId, action, resourceType, resourceId, details = {}, ipAddress = null) {
    if (!(await hasTable("AuditLog"))) {
        return;
    }

    const effectiveUserId = await getEffectiveUserId(userId);

    await execute(
        `INSERT INTO AuditLog (user_id, action, resource_type, resource_id, ip_address, details)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [effectiveUserId, action, resourceType, resourceId, ipAddress, JSON.stringify(details)]
    ).catch((error) => {
        console.error("[AuditLog] Failed to write:", error.message);
    });
}

export async function persistScanResult(scanResult, { userId = DEFAULT_SYSTEM_USER_ID, scanType = "deep_scan" } = {}) {
    const targetIp = scanResult?.host || scanResult?.target || null;
    const simulationId = await createSimulation({
        userId,
        scanType,
        targetIp,
        targetSubnet: null
    });

    try {
        let hostId = null;
        if (scanResult?.status !== "down" && targetIp) {
            const netInfo = scanResult.network_info || {};

            hostId = await upsertHost(simulationId, userId, {
                ipAddress: targetIp,
                macAddress: netInfo.mac_address || null,
                macVendor: netInfo.mac_vendor || null,
                hostname: scanResult.hostname || netInfo.hostname || null,
                osDetection: scanResult.os_detection?.name || null,
                deviceType: netInfo.device_type || null
            });

            if (hostId) {
                await insertPorts(hostId, scanResult.ports || []);
                await insertVulnerabilities(simulationId, hostId, scanResult.vulnerabilities || []);
                await insertCredentialTests(simulationId, hostId, scanResult.credential_tests || [], userId);
            }
        }

        await completeSimulation(simulationId, {
            status: "completed",
            nmapVersion: scanResult?.nmap_version || null,
            nmapCommand: scanResult?.nmap_command || null,
            scanTimeSeconds: parseScanTimeSeconds(scanResult?.scan_time),
            jsonResponse: scanResult
        });

        await logAudit(userId, "simulation_completed", "Simulations", simulationId, {
            target_ip: targetIp,
            ports_found: Array.isArray(scanResult?.ports) ? scanResult.ports.length : 0,
            vulnerabilities_found: Array.isArray(scanResult?.vulnerabilities)
                ? scanResult.vulnerabilities.length
                : 0,
            credential_findings: Array.isArray(scanResult?.credential_tests)
                ? scanResult.credential_tests.filter((item) => item.status === "credentials_found").length
                : 0
        });

        return {
            simulationId,
            hostId
        };
    } catch (error) {
        await completeSimulation(simulationId, {
            status: "failed",
            nmapVersion: scanResult?.nmap_version || null,
            nmapCommand: scanResult?.nmap_command || null,
            scanTimeSeconds: parseScanTimeSeconds(scanResult?.scan_time),
            jsonResponse: scanResult,
            errorMessage: error.message
        }).catch(() => {
            // ignore secondary failure
        });

        throw error;
    }
}

export async function persistDiscoveryResult(discoveryResult, { userId = DEFAULT_SYSTEM_USER_ID } = {}) {
    const simulationId = await createSimulation({
        userId,
        scanType: "discover",
        targetIp: discoveryResult?.subnet || null,
        targetSubnet: discoveryResult?.subnet || null
    });

    try {
        const devices = Array.isArray(discoveryResult?.devices) ? discoveryResult.devices : [];

        for (const device of devices) {
            if (!device?.ip) {
                continue;
            }

            await upsertHost(simulationId, userId, {
                ipAddress: device.ip,
                macAddress: device.mac || null,
                macVendor: device.vendor || null,
                hostname: device.hostname || null
            });
        }

        await completeSimulation(simulationId, {
            status: "completed",
            nmapVersion: discoveryResult?.nmap_version || null,
            nmapCommand: discoveryResult?.nmap_command || null,
            scanTimeSeconds: parseScanTimeSeconds(discoveryResult?.scan_time),
            jsonResponse: discoveryResult
        });

        await logAudit(userId, "discovery_completed", "Simulations", simulationId, {
            subnet: discoveryResult?.subnet || null,
            hosts_found: devices.length
        });

        return simulationId;
    } catch (error) {
        await completeSimulation(simulationId, {
            status: "failed",
            nmapVersion: discoveryResult?.nmap_version || null,
            nmapCommand: discoveryResult?.nmap_command || null,
            scanTimeSeconds: parseScanTimeSeconds(discoveryResult?.scan_time),
            jsonResponse: discoveryResult,
            errorMessage: error.message
        }).catch(() => {
            // ignore secondary failure
        });

        throw error;
    }
}
