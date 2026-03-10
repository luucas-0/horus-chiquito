import { analyzeWithAI, chatWithAIAgent as chatWithAIAgentService } from "../services/ai.service.js";
import { generatePDFReport, validateReportData } from "../services/pdf.service.js";
import {
    getSimulationById,
    isPersistenceEnabled,
    saveAIAnalysis
} from "../services/db.service.js";
import { isOpenAIConfigured } from "../config/openai.config.js";
import { isMailConfigured } from "../config/mail.config.js";
import { sendEmailMessage } from "../services/email.service.js";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REMEDIATION_AUDIT_LOG_PATH = path.join(__dirname, "..", "..", "ai-orchestrator", "engine", "remediation_audit.log");

function parsePositiveInt(value) {
    const parsed = Number.parseInt(String(value ?? ""), 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

function makeControllerError(statusCode, message, details = null) {
    const error = new Error(message);
    error.statusCode = statusCode;

    if (details != null) {
        error.details = details;
    }

    return error;
}

function isValidEmail(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(String(value || "").trim());
}

function formatDateTime(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return String(value || "--");
    }

    return date.toLocaleString("es-ES");
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

function normalizeSeverity(value) {
    const severity = String(value || "").trim().toLowerCase();

    if (["critical", "high", "medium", "low"].includes(severity)) {
        return severity;
    }

    if (["info", "informational", "none"].includes(severity)) {
        return "low";
    }

    return "medium";
}

function toLower(value) {
    return String(value || "").toLowerCase();
}

function buildScanPayloadFromNormalizedEntities(simulation) {
    if (!simulation || !Array.isArray(simulation.hosts) || simulation.hosts.length === 0) {
        return null;
    }

    const primaryHost = simulation.hosts[0];
    if (!primaryHost || !primaryHost.ip_address) {
        return null;
    }

    const ports = Array.isArray(primaryHost.ports)
        ? primaryHost.ports.map((port) => ({
            port: port.port_number ?? port.port ?? null,
            protocol: port.protocol || "tcp",
            state: port.state || "open",
            service: port.service || null,
            product: port.product || null,
            version: port.version || null,
            cpe: port.cpe || null,
            extra_info: port.extra_info || null
        }))
        : [];

    const vulnerabilities = Array.isArray(primaryHost.vulnerabilities)
        ? primaryHost.vulnerabilities.map((vulnerability) => ({
            script_id: vulnerability.script_id || null,
            severity: vulnerability.severity || "medium",
            description: vulnerability.output || vulnerability.description || "Sin detalle adicional.",
            affected_service: vulnerability.port_id ? `port-${vulnerability.port_id}` : null
        }))
        : [];

    const credentialTests = Array.isArray(primaryHost.credential_tests)
        ? primaryHost.credential_tests.map((test) => ({
            service: test.service || null,
            status: test.status || "no_credentials_found",
            port: test.port_id || null,
            risk_score: Number.isFinite(Number.parseFloat(String(test.risk_score ?? "")))
                ? Number.parseFloat(String(test.risk_score))
                : 0
        }))
        : [];

    const hostIp = primaryHost.ip_address || simulation.target_ip || null;

    return {
        host: hostIp,
        hostname: primaryHost.hostname || null,
        status: simulation.status || null,
        scan_time: simulation.scan_time_seconds || null,
        network_info: {
            host_ip: hostIp,
            mac_address: primaryHost.mac_address || null,
            mac_vendor: primaryHost.mac_vendor || null,
            hostname: primaryHost.hostname || null,
            device_type: primaryHost.device_type || null,
            vulnerabilities_count: vulnerabilities.length,
            open_ports_count: ports.filter(
                (port) => toLower(port.state || "open") === "open"
            ).length
        },
        ports,
        vulnerabilities,
        credential_tests: credentialTests
    };
}

function extractScanPayloadFromSimulation(simulation) {
    const payload = safeJsonParse(simulation?.json_response, null);

    if (!payload || typeof payload !== "object") {
        return null;
    }

    // Deep scan payloads
    if (payload.host || payload.ports || payload.network_info) {
        return payload;
    }

    // Network discovery payloads
    if (payload.subnet && (payload.devices || payload.hosts_up != null)) {
        return payload;
    }

    if (payload.scan_result && typeof payload.scan_result === "object") {
        return payload.scan_result;
    }

    if (payload.result && typeof payload.result === "object") {
        return payload.result;
    }

    const normalizedPayload = buildScanPayloadFromNormalizedEntities(simulation);

    if (normalizedPayload) {
        return normalizedPayload;
    }

    return null;
}

function isDiscoveryPayload(payload) {
    return payload && payload.subnet && (Array.isArray(payload.devices) || payload.hosts_up != null) && !payload.ports;
}

function buildDiscoveryAnalysis(payload) {
    const devices = Array.isArray(payload.devices) ? payload.devices : [];
    const hostsUp = payload.hosts_up || devices.length;
    const subnet = payload.subnet || "unknown";
    const scanTime = payload.scan_time || "?";

    const devicesWithMac = devices.filter(d => d.mac);
    const devicesWithHostname = devices.filter(d => d.hostname);
    const uniqueVendors = [...new Set(devices.map(d => d.vendor).filter(Boolean))];

    const riskFactors = [];
    let riskScore = 1.0;

    if (hostsUp > 20) {
        riskScore += 1.5;
        riskFactors.push(`Alta densidad de hosts activos (${hostsUp}) en la subred.`);
    }

    const unknownDevices = devices.filter(d => !d.mac && !d.hostname);
    if (unknownDevices.length > 0) {
        riskScore += 0.8;
        riskFactors.push(`${unknownDevices.length} dispositivo(s) sin MAC ni hostname identificado.`);
    }

    if (devicesWithMac.length < devices.length * 0.5 && devices.length > 2) {
        riskScore += 0.5;
        riskFactors.push("Menos del 50% de los hosts tienen MAC visible (posible segmentacion o NAT).");
    }

    riskScore = Math.max(0, Math.min(10, Math.round(riskScore * 10) / 10));
    const riskLevel = riskLevelFromScore(riskScore);

    const actions = [
        "Realizar escaneo profundo (deep scan) en cada host descubierto para identificar servicios y vulnerabilidades.",
        "Documentar todos los dispositivos en un inventario de activos de red.",
        "Verificar que cada dispositivo descubierto este autorizado en la red."
    ];

    if (unknownDevices.length > 0) {
        actions.push("Investigar dispositivos sin identificacion (sin MAC/hostname) para descartar equipos no autorizados.");
    }

    const summary =
        `Descubrimiento de red completado en subred ${subnet}. ` +
        `Hosts activos: ${hostsUp}. ` +
        `Dispositivos con MAC: ${devicesWithMac.length}. ` +
        `Dispositivos con hostname: ${devicesWithHostname.length}. ` +
        `Fabricantes detectados: ${uniqueVendors.length > 0 ? uniqueVendors.join(", ") : "ninguno"}. ` +
        `Tiempo de escaneo: ${scanTime}s.`;

    return {
        executive_summary: summary,
        overall_risk_score: riskScore,
        risk_level: riskLevel,
        scan_metadata: {
            host: subnet,
            scan_type: "discovery",
            scan_profile: payload.scan_profile || null,
            analyzer: "local_heuristic",
            hosts_discovered: hostsUp,
            generated_at: new Date().toISOString()
        },
        vulnerabilities: riskFactors.map((factor, i) => ({
            title: `Hallazgo de descubrimiento #${i + 1}`,
            script_id: null,
            severity: riskScore > 3 ? "medium" : "low",
            description: factor,
            impact: "Requiere investigacion adicional con escaneo profundo.",
            affected_component: subnet,
            cve_id: "N/A"
        })),
        network_exposure: {
            subnet,
            hosts_discovered: hostsUp,
            devices_with_mac: devicesWithMac.length,
            devices_with_hostname: devicesWithHostname.length,
            vendors: uniqueVendors,
            unknown_devices_count: unknownDevices.length
        },
        compliance_notes: {
            note: "Analisis basado en descubrimiento de red. Ejecutar escaneo profundo para evaluacion completa."
        },
        immediate_actions: actions,
        recommendations: actions,
        analysis_confidence: 0.4,
        generated_at: new Date().toISOString(),
        model_version: "local-heuristic-discovery-v1",
        fallback_mode: true
    };
}

function extractStoredAiAnalysis(simulation) {
    if (simulation?.ai_analysis) {
        return simulation.ai_analysis;
    }

    const payload = safeJsonParse(simulation?.json_response, null);
    return payload?.ai_analysis || null;
}

function buildPdfRecommendations(analysis) {
    if (Array.isArray(analysis?.recommendations) && analysis.recommendations.length > 0) {
        return analysis.recommendations.map((item, index) => {
            if (typeof item === "string") {
                return {
                    title: `Recomendacion ${index + 1}`,
                    description: item
                };
            }

            return {
                title: item?.title || `Recomendacion ${index + 1}`,
                description: item?.description || item?.action || "Sin detalle"
            };
        });
    }

    if (Array.isArray(analysis?.immediate_actions) && analysis.immediate_actions.length > 0) {
        return analysis.immediate_actions.map((action, index) => ({
            title: `Accion inmediata ${index + 1}`,
            description: String(action)
        }));
    }

    return [
        {
            title: "Aplicar hardening inicial",
            description: "Revisar puertos expuestos, credenciales y versiones de servicios antes de pasar a produccion."
        }
    ];
}

function buildEnrichedExecutiveSummary(rawSummary, riskScore, riskCategory, vulnerabilities) {
    const baseSummary = (rawSummary && String(rawSummary).trim()) ||
        "Analisis generado automaticamente por el modulo de IA de HORUS.";

    const riskExplanations = {
        Critico:
            "El nivel de riesgo CRITICO indica que se encontraron problemas de seguridad graves que " +
            "requieren atencion inmediata. El sistema analizado es altamente vulnerable y podria ser " +
            "comprometido por un atacante con conocimientos basicos. Se recomienda no exponer este " +
            "equipo a redes no confiables hasta corregir todos los hallazgos criticos.",
        Alto:
            "El nivel de riesgo ALTO indica que existen multiples vulnerabilidades significativas. " +
            "Un atacante motivado podria explotar estas debilidades para obtener acceso no autorizado " +
            "al sistema. Es necesario planificar acciones correctivas a corto plazo.",
        Medio:
            "El nivel de riesgo MEDIO indica que se detectaron algunas debilidades que, si bien no " +
            "representan un peligro inmediato, podrian ser explotadas en combinacion con otros factores. " +
            "Se recomienda atender los hallazgos de forma planificada.",
        Bajo:
            "El nivel de riesgo BAJO indica que el sistema presenta una postura de seguridad aceptable, " +
            "aunque siempre es recomendable mantener actualizaciones y monitoreo continuo."
    };

    const criticalCount = vulnerabilities.filter((v) => normalizeSeverity(v.severity) === "critical").length;
    const highCount = vulnerabilities.filter((v) => normalizeSeverity(v.severity) === "high").length;
    const mediumCount = vulnerabilities.filter((v) => normalizeSeverity(v.severity) === "medium").length;
    const hasCredentials = vulnerabilities.some((v) =>
        toLower(v.title).includes("credencial") || toLower(v.script_id || "").includes("hydra")
    );

    const parts = [baseSummary];

    parts.push(riskExplanations[riskCategory] || riskExplanations.Bajo);

    if (vulnerabilities.length > 0) {
        const breakdown = [];
        if (criticalCount > 0) breakdown.push(`${criticalCount} critico(s)`);
        if (highCount > 0) breakdown.push(`${highCount} alto(s)`);
        if (mediumCount > 0) breakdown.push(`${mediumCount} medio(s)`);

        parts.push(
            `Resumen de hallazgos: se identificaron ${vulnerabilities.length} hallazgo(s) en total` +
            (breakdown.length > 0 ? ` (${breakdown.join(", ")})` : "") + "."
        );
    }

    if (hasCredentials) {
        parts.push(
            "ALERTA DE CREDENCIALES: Se encontraron contrasenas debiles o predecibles en uno o mas " +
            "servicios. Esto significa que un atacante podria acceder al sistema usando las mismas " +
            "combinaciones de usuario y contrasena descubiertas. Es imprescindible cambiar estas " +
            "credenciales de inmediato."
        );
    }

    return parts.join("\n\n");
}

function summarizeRemediationExplanation(entry) {
    const execution = entry?.execution || {};
    const findingType = String(entry?.finding?.finding_type || "hallazgo");
    const commands = Array.isArray(execution.commands)
        ? execution.commands.filter(Boolean).map((item) => String(item).trim()).filter(Boolean)
        : [];
    const actions = Array.isArray(execution.actions)
        ? execution.actions.filter(Boolean).map((item) => String(item).trim()).filter(Boolean)
        : [];

    if (execution.executed) {
        const details = [];
        if (commands.length > 0) {
            details.push("Comando(s) aplicado(s): " + commands.join(" | ") + ".");
        }
        if (actions.length > 0) {
            details.push("Accion(es) aplicada(s): " + actions.join(", ") + ".");
        }

        return ("HORUS aplico remediacion para " + findingType + ". " + (details.join(" ") || "Se aplico una contencion controlada.")).trim();
    }

    if (execution.queued) {
        const details = [];
        if (commands.length > 0) {
            details.push("Pendiente ejecutar comando(s): " + commands.join(" | ") + ".");
        }
        if (actions.length > 0) {
            details.push("Pendiente ejecutar accion(es): " + actions.join(", ") + ".");
        }

        return ("La remediacion para " + findingType + " quedo en cola. " + (execution.message || "Requiere aprobacion manual.") + " " + details.join(" ")).trim();
    }

    return String(execution.message || ("No se aplico remediacion automatica para " + findingType + "."));
}

function buildRemediationBlindajeExplanation(remediationActivity) {
    const entries = Array.isArray(remediationActivity)
        ? remediationActivity.filter((item) => item && typeof item === "object")
        : [];

    const executed = entries.filter((item) => Boolean(item.executed));
    if (executed.length === 0) {
        return null;
    }

    const byFindingType = new Map();
    for (const item of executed) {
        const findingType = String(item.finding_type || "hallazgo");
        const bucket = byFindingType.get(findingType) || [];
        bucket.push(item);
        byFindingType.set(findingType, bucket);
    }

    const overview = [
        "HORUS aplico remediacion controlada para blindar las brechas detectadas.",
        `Se ejecutaron ${executed.length} accion(es) sobre ${byFindingType.size} tipo(s) de hallazgo.`
    ];

    const details = [];
    for (const [findingType, items] of byFindingType.entries()) {
        const commandSet = new Set();
        const actionSet = new Set();

        for (const item of items) {
            const commands = Array.isArray(item.commands) ? item.commands : [];
            const actions = Array.isArray(item.actions) ? item.actions : [];
            for (const command of commands) {
                if (command) {
                    commandSet.add(String(command));
                }
            }
            for (const action of actions) {
                if (action) {
                    actionSet.add(String(action));
                }
            }
        }

        const commandText = commandSet.size > 0
            ? "Comandos: " + Array.from(commandSet).join(" | ") + "."
            : "Comandos: no aplica.";
        const actionText = actionSet.size > 0
            ? "Acciones: " + Array.from(actionSet).join(", ") + "."
            : "Acciones: no aplica.";

        details.push(`- ${findingType}: ${commandText} ${actionText}`);
    }

    return [...overview, ...details].join("\n");
}

function loadRecentRemediationActivity({ target = null, limit = 8 } = {}) {
    if (!fs.existsSync(REMEDIATION_AUDIT_LOG_PATH)) {
        return [];
    }

    let lines = [];

    try {
        lines = fs.readFileSync(REMEDIATION_AUDIT_LOG_PATH, "utf-8")
            .split(/\r?\n/)
            .map((line) => line.trim())
            .filter(Boolean);
    } catch {
        return [];
    }

    if (lines.length === 0) {
        return [];
    }

    const parsedEntries = lines
        .map((line) => {
            try {
                return JSON.parse(line);
            } catch {
                return null;
            }
        })
        .filter((entry) => entry && typeof entry === "object" && entry.execution && entry.finding);

    if (parsedEntries.length === 0) {
        return [];
    }

    const targetText = String(target || "").trim();
    const scopedByTarget = targetText
        ? parsedEntries.filter((entry) => {
            const findingTarget = String(
                entry?.finding?.details?.target || entry?.finding?.target || ""
            ).trim();

            return findingTarget !== "" && findingTarget === targetText;
        })
        : parsedEntries;

    const sourceEntries = targetText ? scopedByTarget : parsedEntries;
    const recent = sourceEntries.slice(-Math.max(limit * 3, limit)).reverse();

    const unique = [];
    const seen = new Set();

    for (const entry of recent) {
        const execution = entry.execution || {};
        const key = [
            String(execution.finding_id || entry?.finding?.id || "unknown"),
            String(entry.action || "unknown"),
            String(Boolean(execution.executed)),
            String(Boolean(execution.queued)),
            String(entry?.finding?.finding_type || "unknown")
        ].join("|");

        if (seen.has(key)) {
            continue;
        }

        seen.add(key);

        unique.push({
            timestamp: entry.timestamp || null,
            action: entry.action || null,
            finding_id: execution.finding_id || entry?.finding?.id || null,
            finding_type: entry?.finding?.finding_type || null,
            severity: entry?.finding?.severity || null,
            executed: Boolean(execution.executed),
            queued: Boolean(execution.queued),
            message: execution.message || null,
            commands: Array.isArray(execution.commands) ? execution.commands.filter(Boolean) : [],
            actions: Array.isArray(execution.actions) ? execution.actions.filter(Boolean) : [],
            explanation: summarizeRemediationExplanation(entry)
        });

        if (unique.length >= limit) {
            break;
        }
    }

    return unique;
}

function normalizeAnalysisForPdf(rawAnalysis, simulationId, remediationActivity = []) {
    if (!rawAnalysis || typeof rawAnalysis !== "object") {
        return null;
    }

    if (rawAnalysis.analysis_metadata && typeof rawAnalysis.risk_score === "number") {
        return rawAnalysis;
    }

    const analysis = rawAnalysis.findings && typeof rawAnalysis.findings === "object"
        ? rawAnalysis.findings
        : rawAnalysis;

    const vulnerabilities = Array.isArray(analysis.vulnerabilities) ? analysis.vulnerabilities : [];

    const riskFromRow = typeof rawAnalysis.risk_score_global === "number" ? rawAnalysis.risk_score_global : null;

    const normalizedVulnerabilities = vulnerabilities.map((vulnerability, index) => {
        const base = {
            title:
                vulnerability?.title ||
                vulnerability?.script_id ||
                vulnerability?.affected_service ||
                `Vulnerabilidad ${index + 1}`,
            severity: normalizeSeverity(vulnerability?.severity),
            description: vulnerability?.description || vulnerability?.output || "Sin descripcion detallada.",
            impact:
                vulnerability?.impact ||
                (Array.isArray(vulnerability?.attack_vectors)
                    ? `Vectores: ${vulnerability.attack_vectors.join(", ")}`
                    : "Impacto potencial sobre confidencialidad, integridad y disponibilidad."),
            affected_component:
                vulnerability?.affected_component || vulnerability?.affected_service || "Componente no especificado",
            cve_id:
                vulnerability?.cve_id ||
                (Array.isArray(vulnerability?.references)
                    ? vulnerability.references.find((item) => String(item).toUpperCase().startsWith("CVE-")) || "N/A"
                    : "N/A")
        };

        return enrichVulnerabilityForReport(base);
    });

    const riskRaw = Number.parseFloat(
        String(
            analysis.overall_risk_score ??
            analysis.risk_score_global ??
            analysis.risk_score ??
            (riskFromRow != null ? riskFromRow : 0)
        )
    );

    const riskScore = Number.isFinite(riskRaw)
        ? riskRaw <= 10
            ? Math.max(0, Math.min(100, Math.round(riskRaw * 10)))
            : Math.max(0, Math.min(100, Math.round(riskRaw)))
        : (riskFromRow != null ? Math.max(0, Math.min(100, riskFromRow)) : 0);

    const riskCategory = riskScore >= 80 ? "Critico" : riskScore >= 60 ? "Alto" : riskScore >= 40 ? "Medio" : "Bajo";

    const enrichedSummary = buildEnrichedExecutiveSummary(
        analysis.executive_summary,
        riskScore,
        riskCategory,
        normalizedVulnerabilities
    );

    const normalizedRemediationActivity = Array.isArray(remediationActivity)
        ? remediationActivity
        : [];
    const remediationApplied = normalizedRemediationActivity.some((item) => Boolean(item?.executed));
    const remediationBlindajeExplanation = buildRemediationBlindajeExplanation(normalizedRemediationActivity);

    return {
        analysis_metadata: {
            analysis_id: `AI-${simulationId}-${Date.now()}`,
            simulation_id: String(simulationId),
            analyzed_at: analysis.generated_at || new Date().toISOString(),
            model_version: analysis.model_version || "gpt"
        },
        executive_summary: enrichedSummary,
        risk_score: riskScore,
        vulnerabilities: normalizedVulnerabilities,
        recommendations: remediationApplied ? [] : buildPdfRecommendations(analysis),
        remediation_activity: normalizedRemediationActivity,
        remediation_applied: remediationApplied,
        remediation_blindaje_explanation: remediationBlindajeExplanation
    };
}

function normalizeRiskScoreTo100(value) {
    const riskRaw = Number.parseFloat(String(value ?? "0"));
    if (!Number.isFinite(riskRaw)) {
        return 0;
    }

    if (riskRaw <= 10) {
        return Math.max(0, Math.min(100, Math.round(riskRaw * 10)));
    }

    return Math.max(0, Math.min(100, Math.round(riskRaw)));
}

function severityWeight(severity) {
    const normalized = normalizeSeverity(severity);
    if (normalized === "critical") return 2.5;
    if (normalized === "high") return 1.7;
    if (normalized === "medium") return 1.0;
    return 0.4;
}

function riskLevelFromScore(score) {
    if (score >= 8.5) return "CRITICAL";
    if (score >= 6.5) return "HIGH";
    if (score >= 4.0) return "MEDIUM";
    return "LOW";
}

const VULN_KNOWLEDGE = {
    ftp_exposed: {
        keywords: ["ftp expuesto", "ftp exposed"],
        plain_description:
            "Se detecto que el servicio FTP (protocolo de transferencia de archivos) esta disponible y " +
            "accesible desde la red. FTP es un protocolo antiguo que transmite nombres de usuario, contrasenas " +
            "y archivos sin ningun tipo de cifrado, lo que significa que cualquier persona en la misma red " +
            "podria interceptar esta informacion facilmente.",
        business_impact:
            "Un atacante podria capturar credenciales de acceso y archivos confidenciales que se transfieran " +
            "por este servicio. Esto puede llevar a robo de informacion sensible, modificacion de archivos " +
            "criticos o uso del servidor como punto de entrada a otros sistemas de la organizacion.",
        what_to_do:
            "Desactive el servicio FTP si no es estrictamente necesario. Si necesita transferir archivos, " +
            "migre a SFTP o FTPS, que cifran la comunicacion. Asegurese de usar contrasenas robustas y " +
            "restrinja el acceso solo a las personas que lo necesiten."
    },
    ftp_anonymous: {
        keywords: ["ftp anonimo", "ftp anon", "anonymous ftp"],
        plain_description:
            "El servidor FTP permite que cualquier persona se conecte sin necesidad de un usuario o contrasena " +
            "(acceso anonimo). Esto significa que cualquiera en la red puede explorar y posiblemente descargar " +
            "archivos almacenados en el servidor sin ninguna restriccion.",
        business_impact:
            "Archivos internos, configuraciones, datos de clientes u otra informacion sensible podrian ser " +
            "accedidos por personas no autorizadas. Ademas, un atacante podria subir archivos maliciosos " +
            "(malware, scripts) al servidor para comprometer otros sistemas.",
        what_to_do:
            "Desactive inmediatamente el acceso anonimo en la configuracion del servidor FTP. Configure " +
            "cuentas individuales con contrasenas fuertes para cada usuario que necesite acceso. " +
            "Revise que archivos estan actualmente expuestos y evalúe si contienen informacion sensible."
    },
    telnet_exposed: {
        keywords: ["telnet expuesto", "telnet exposed"],
        plain_description:
            "El servicio Telnet esta habilitado y accesible. Telnet es un protocolo de acceso remoto muy " +
            "antiguo e inseguro que transmite todo en texto plano, incluyendo contrasenas. Es considerado " +
            "uno de los servicios mas peligrosos que puede tener un equipo conectado a la red.",
        business_impact:
            "Cualquier atacante en la red puede interceptar las credenciales de administracion del equipo. " +
            "Una vez obtenidas, tendria control total sobre el dispositivo, pudiendo acceder a datos, " +
            "instalar software malicioso o usar el equipo para atacar otros sistemas internos.",
        what_to_do:
            "Desactive Telnet de inmediato y reemplacelo con SSH (Secure Shell), que cifra toda la " +
            "comunicacion. Si el equipo no soporta SSH, considere reemplazarlo por uno mas moderno. " +
            "Cambie todas las contrasenas que se hayan usado a traves de Telnet, ya que podrian estar comprometidas."
    },
    smb_exposed: {
        keywords: ["smb expuesto", "smb exposed", "netbios"],
        plain_description:
            "El servicio SMB (protocolo para compartir archivos e impresoras en red) esta accesible. " +
            "SMB ha sido historicamente una de las vias de ataque mas explotadas. Vulnerabilidades en " +
            "SMB han sido usadas en ataques globales como WannaCry y NotPetya que afectaron a miles de empresas.",
        business_impact:
            "Un atacante podria acceder a carpetas compartidas, documentos internos y recursos de red. " +
            "En el peor escenario, podria ejecutar codigo malicioso de forma remota, lo que le daria " +
            "control total sobre el equipo y permitiria propagar malware a toda la red.",
        what_to_do:
            "Restrinja el acceso a SMB solo a los equipos que realmente lo necesiten mediante reglas de " +
            "firewall. Desactive SMBv1 (version antigua vulnerable). Aplique todas las actualizaciones " +
            "de seguridad disponibles. Asegurese de que las carpetas compartidas tengan permisos minimos."
    },
    credentials_found: {
        keywords: ["credenciales debiles", "credenciales encontradas", "credentials_found", "hydra-credentials", "credentials found"],
        plain_description:
            "Durante la prueba de seguridad se logro adivinar una combinacion de usuario y contrasena valida " +
            "para acceder a un servicio del equipo. Esto significa que las credenciales configuradas son " +
            "debiles, comunes o predecibles, y un atacante tambien podria descubrirlas facilmente.",
        business_impact:
            "IMPACTO CRITICO: Un atacante puede iniciar sesion en el servicio con estas credenciales y " +
            "obtener acceso inmediato al sistema. Desde ahi puede robar informacion, modificar configuraciones, " +
            "instalar malware o moverse lateralmente hacia otros equipos de la red interna.",
        what_to_do:
            "ACCION URGENTE: Cambie inmediatamente las contrasenas comprometidas por contrasenas fuertes " +
            "(minimo 12 caracteres, combinando mayusculas, minusculas, numeros y simbolos). Active la " +
            "autenticacion de dos factores (2FA/MFA) si el servicio lo permite. Configure politicas de " +
            "bloqueo de cuenta despues de varios intentos fallidos para evitar ataques de fuerza bruta."
    },
    rdp_exposed: {
        keywords: ["rdp expuesto", "rdp exposed", "remote desktop"],
        plain_description:
            "El servicio de Escritorio Remoto (RDP) esta expuesto en la red. RDP permite controlar " +
            "visualmente un equipo de forma remota, como si estuviera sentado frente a el.",
        business_impact:
            "Si un atacante logra acceder via RDP, tendria control total e interactivo del equipo, " +
            "pudiendo ver pantallas, abrir archivos, instalar programas y acceder a todos los recursos " +
            "del usuario. Es uno de los vectores mas usados en ataques de ransomware.",
        what_to_do:
            "No exponga RDP directamente a la red. Use una VPN para acceder remotamente. Active " +
            "autenticacion en dos pasos (NLA + MFA). Configure politicas de bloqueo de cuenta " +
            "y monitoree los intentos de acceso."
    },
    mysql_exposed: {
        keywords: ["mysql expuesto", "mysql exposed"],
        plain_description:
            "El servidor de base de datos MySQL esta accesible desde la red. Las bases de datos " +
            "contienen la informacion mas valiosa de una organizacion: datos de clientes, registros " +
            "financieros, contrasenas, etc.",
        business_impact:
            "Si un atacante accede a la base de datos, podria robar, modificar o borrar toda la " +
            "informacion almacenada. Esto puede resultar en filtraciones de datos personales, " +
            "perdida de informacion critica y sanciones legales por incumplimiento de proteccion de datos.",
        what_to_do:
            "Restrinja el acceso a MySQL solo desde los servidores de aplicacion que lo necesiten " +
            "(nunca exponerlo a internet). Use contrasenas fuertes y cuentas con permisos minimos. " +
            "Active el registro de accesos para detectar actividad sospechosa."
    },
    redis_exposed: {
        keywords: ["redis expuesto", "redis exposed"],
        plain_description:
            "El servidor Redis (almacen de datos en memoria) esta accesible. Redis frecuentemente " +
            "no tiene autenticacion configurada por defecto, lo que permite acceso libre.",
        business_impact:
            "Un atacante podria leer datos en cache (que puede incluir sesiones de usuario, tokens " +
            "de acceso o datos sensibles), borrar toda la informacion o incluso ejecutar comandos " +
            "en el servidor.",
        what_to_do:
            "Configure autenticacion (requirepass). Restrinja Redis a localhost o red interna. " +
            "Deshabilite el acceso publico y los comandos peligrosos (CONFIG, FLUSHALL)."
    },
    network_exposure: {
        keywords: ["superficie de exposicion", "network exposure"],
        plain_description:
            "Se identificaron puertos de red abiertos que amplian la superficie de ataque del " +
            "equipo. Cada puerto abierto es una potencial puerta de entrada para un atacante.",
        business_impact:
            "Servicios innecesarios expuestos aumentan las oportunidades de que un atacante " +
            "encuentre una via para comprometer el sistema.",
        what_to_do:
            "Revise cada puerto abierto y cierre los que no sean esenciales para el funcionamiento " +
            "del equipo. Configure un firewall para limitar el acceso solo a servicios necesarios."
    },
    smb_signing_disabled: {
        keywords: ["signing disabled", "signing enabled but not required", "firma smb"],
        plain_description:
            "La firma de mensajes SMB esta desactivada o no es obligatoria. La firma digital en SMB " +
            "verifica que los datos no hayan sido alterados durante la transmision.",
        business_impact:
            "Sin firma obligatoria, un atacante podria interceptar y modificar la comunicacion entre " +
            "equipos (ataque man-in-the-middle), redirigiendo archivos, credenciales o ejecutando " +
            "comandos en nombre de un usuario legitimo.",
        what_to_do:
            "Active y haga obligatoria la firma SMB en todos los equipos de la red. Esto se configura " +
            "en las politicas de grupo (GPO) en entornos Windows o en la configuracion de Samba en Linux."
    }
};

function enrichVulnerabilityForReport(vulnerability) {
    const titleLower = toLower(vulnerability?.title);
    const descLower = toLower(vulnerability?.description);
    const combined = `${titleLower} ${descLower}`;

    for (const [, knowledge] of Object.entries(VULN_KNOWLEDGE)) {
        const matched = knowledge.keywords.some((keyword) => combined.includes(keyword));

        if (matched) {
            return {
                ...vulnerability,
                plain_description: knowledge.plain_description,
                business_impact: knowledge.business_impact,
                what_to_do: knowledge.what_to_do
            };
        }
    }

    return {
        ...vulnerability,
        plain_description:
            vulnerability?.description ||
            "Se detecto un hallazgo de seguridad que requiere atencion. Consulte con su equipo " +
            "de tecnologia para evaluar el impacto y las acciones necesarias.",
        business_impact:
            vulnerability?.impact ||
            "Este hallazgo podria comprometer la confidencialidad, integridad o disponibilidad " +
            "de sus sistemas si no se atiende oportunamente.",
        what_to_do:
            "Consulte con su equipo de seguridad informatica para evaluar este hallazgo y " +
            "aplicar las medidas correctivas apropiadas."
    };
}

/* ═══════════════════════════════════════════════════════════════
   REMEDIATION PLAYBOOKS — Planes de acción por vulnerabilidad
   ═══════════════════════════════════════════════════════════════ */

const REMEDIATION_PLAYBOOKS = {
    ftp_exposed: {
        keywords: ["ftp expuesto", "ftp exposed", "21/tcp", "ftp sin cifrado"],
        priority: "critica",
        title: "Deshabilitar FTP y migrar a SFTP",
        risk_of_change: "El servicio FTP dejara de funcionar. Los usuarios deben usar SFTP en su lugar.",
        steps: {
            linux: [
                {
                    action: "Detener y deshabilitar el servicio FTP",
                    commands: [
                        "sudo systemctl stop vsftpd",
                        "sudo systemctl disable vsftpd"
                    ],
                    explanation: "Apaga el servicio FTP inseguro para que no transmita datos sin cifrado."
                },
                {
                    action: "Verificar que SSH/SFTP esta activo",
                    commands: [
                        "sudo systemctl status sshd",
                        "sudo systemctl enable sshd --now"
                    ],
                    explanation: "SFTP funciona sobre SSH, que ya cifra toda la comunicacion."
                },
                {
                    action: "Configurar SFTP con acceso restringido",
                    commands: [
                        "echo 'Match Group sftpusers' | sudo tee -a /etc/ssh/sshd_config",
                        "echo '    ChrootDirectory /home/%u' | sudo tee -a /etc/ssh/sshd_config",
                        "echo '    ForceCommand internal-sftp' | sudo tee -a /etc/ssh/sshd_config",
                        "echo '    AllowTcpForwarding no' | sudo tee -a /etc/ssh/sshd_config",
                        "sudo systemctl restart sshd"
                    ],
                    explanation: "Limita a los usuarios SFTP a su directorio home, sin acceso shell."
                },
                {
                    action: "Bloquear puerto 21 en el firewall",
                    commands: [
                        "sudo ufw deny 21/tcp",
                        "sudo ufw reload"
                    ],
                    explanation: "Cierra el puerto FTP para que nadie pueda conectarse aunque el servicio se reactive."
                }
            ],
            windows: [
                {
                    action: "Detener el servicio FTP de IIS",
                    commands: [
                        "net stop ftpsvc",
                        "sc config ftpsvc start= disabled"
                    ],
                    explanation: "Detiene y deshabilita el servicio FTP en Windows."
                },
                {
                    action: "Instalar y configurar OpenSSH Server para SFTP",
                    commands: [
                        "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0",
                        "Start-Service sshd",
                        "Set-Service -Name sshd -StartupType Automatic"
                    ],
                    explanation: "Instala el servidor SSH nativo de Windows que incluye SFTP seguro."
                },
                {
                    action: "Bloquear puerto 21 en Windows Firewall",
                    commands: [
                        "netsh advfirewall firewall add rule name=\"Block FTP\" dir=in action=block protocol=tcp localport=21"
                    ],
                    explanation: "Regla de firewall que impide conexiones FTP entrantes."
                }
            ]
        },
        verification: [
            "nmap -p 21 {TARGET} — Debe mostrar 'closed' o 'filtered'",
            "sftp usuario@{TARGET} — Debe conectar exitosamente por SFTP"
        ]
    },

    ftp_anonymous: {
        keywords: ["ftp anonimo", "ftp anonymous", "anonymous ftp"],
        priority: "critica",
        title: "Deshabilitar acceso FTP anonimo",
        risk_of_change: "Los usuarios que accedian sin credenciales deberan autenticarse.",
        steps: {
            linux: [
                {
                    action: "Deshabilitar acceso anonimo en vsftpd",
                    commands: [
                        "sudo sed -i 's/anonymous_enable=YES/anonymous_enable=NO/' /etc/vsftpd.conf",
                        "sudo systemctl restart vsftpd"
                    ],
                    explanation: "Modifica la configuracion para requerir autenticacion obligatoria."
                },
                {
                    action: "Verificar que no hay acceso anonimo",
                    commands: [
                        "ftp {TARGET} — Intentar login como 'anonymous' debe fallar"
                    ],
                    explanation: "Confirma que el acceso sin contrasena ya no es posible."
                }
            ],
            windows: [
                {
                    action: "Deshabilitar autenticacion anonima en IIS FTP",
                    commands: [
                        "appcmd set config /section:anonymousAuthentication /enabled:false",
                        "iisreset"
                    ],
                    explanation: "Desactiva el acceso anonimo en el servidor FTP de IIS."
                }
            ]
        },
        verification: [
            "ftp {TARGET} con usuario 'anonymous' — Debe rechazar la conexion"
        ]
    },

    telnet_exposed: {
        keywords: ["telnet expuesto", "telnet exposed", "23/tcp", "telnet"],
        priority: "critica",
        title: "Deshabilitar Telnet y usar SSH",
        risk_of_change: "Los administradores que usaban Telnet deberan conectarse por SSH.",
        steps: {
            linux: [
                {
                    action: "Detener y deshabilitar Telnet",
                    commands: [
                        "sudo systemctl stop telnet.socket inetd xinetd 2>/dev/null",
                        "sudo systemctl disable telnet.socket inetd xinetd 2>/dev/null",
                        "sudo apt remove telnetd -y 2>/dev/null || sudo yum remove telnet-server -y 2>/dev/null"
                    ],
                    explanation: "Elimina completamente el servicio Telnet del sistema."
                },
                {
                    action: "Instalar y configurar SSH seguro",
                    commands: [
                        "sudo apt install openssh-server -y 2>/dev/null || sudo yum install openssh-server -y 2>/dev/null",
                        "sudo systemctl enable sshd --now",
                        "sudo sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
                        "sudo sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
                        "sudo systemctl restart sshd"
                    ],
                    explanation: "Instala SSH con configuracion segura: sin root directo, preferencia por llaves."
                },
                {
                    action: "Generar par de llaves SSH (en el equipo del administrador)",
                    commands: [
                        "ssh-keygen -t ed25519 -C 'admin@empresa'",
                        "ssh-copy-id usuario@{TARGET}"
                    ],
                    explanation: "Crea autenticacion por llave publica, mucho mas segura que contrasenas."
                },
                {
                    action: "Bloquear puerto 23",
                    commands: [
                        "sudo ufw deny 23/tcp",
                        "sudo ufw reload"
                    ],
                    explanation: "Cierra el puerto Telnet en el firewall."
                }
            ],
            windows: [
                {
                    action: "Deshabilitar Telnet Server",
                    commands: [
                        "dism /online /Disable-Feature /FeatureName:TelnetServer",
                        "sc config TlntSvr start= disabled"
                    ],
                    explanation: "Desinstala el feature de Telnet Server en Windows."
                },
                {
                    action: "Bloquear puerto 23",
                    commands: [
                        "netsh advfirewall firewall add rule name=\"Block Telnet\" dir=in action=block protocol=tcp localport=23"
                    ],
                    explanation: "Regla de firewall bloqueando Telnet."
                }
            ]
        },
        verification: [
            "nmap -p 23 {TARGET} — Debe mostrar 'closed' o 'filtered'",
            "ssh usuario@{TARGET} — Debe conectar exitosamente"
        ]
    },

    smb_exposed: {
        keywords: ["smb expuesto", "smb exposed", "445/tcp", "139/tcp", "samba"],
        priority: "alta",
        title: "Restringir y asegurar SMB",
        risk_of_change: "Los compartidos de red seguiran funcionando pero solo desde redes autorizadas.",
        steps: {
            linux: [
                {
                    action: "Restringir acceso SMB por red",
                    commands: [
                        "echo 'hosts allow = 192.168.0.0/16 172.16.0.0/12 10.0.0.0/8' | sudo tee -a /etc/samba/smb.conf",
                        "echo 'hosts deny = 0.0.0.0/0' | sudo tee -a /etc/samba/smb.conf",
                        "sudo systemctl restart smbd"
                    ],
                    explanation: "Permite SMB solo desde redes internas privadas."
                },
                {
                    action: "Habilitar firma SMB obligatoria",
                    commands: [
                        "echo 'server signing = mandatory' | sudo tee -a /etc/samba/smb.conf",
                        "echo 'server min protocol = SMB2' | sudo tee -a /etc/samba/smb.conf",
                        "sudo systemctl restart smbd"
                    ],
                    explanation: "Obliga firma digital en la comunicacion SMB para prevenir ataques man-in-the-middle."
                },
                {
                    action: "Bloquear SMB desde redes externas",
                    commands: [
                        "sudo ufw deny from any to any port 445 proto tcp",
                        "sudo ufw deny from any to any port 139 proto tcp",
                        "sudo ufw allow from 192.168.0.0/16 to any port 445 proto tcp",
                        "sudo ufw reload"
                    ],
                    explanation: "Solo permite SMB desde la red interna."
                }
            ],
            windows: [
                {
                    action: "Habilitar firma SMB obligatoria via GPO",
                    commands: [
                        "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force",
                        "Set-SmbClientConfiguration -RequireSecuritySignature $true -Force"
                    ],
                    explanation: "Activa firma SMB obligatoria en servidor y cliente Windows."
                },
                {
                    action: "Deshabilitar SMBv1",
                    commands: [
                        "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
                        "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
                    ],
                    explanation: "SMBv1 tiene vulnerabilidades criticas conocidas (WannaCry, EternalBlue)."
                },
                {
                    action: "Restringir acceso SMB por firewall",
                    commands: [
                        "netsh advfirewall firewall add rule name=\"Block SMB External\" dir=in action=block protocol=tcp localport=445 remoteip=any",
                        "netsh advfirewall firewall add rule name=\"Allow SMB Internal\" dir=in action=allow protocol=tcp localport=445 remoteip=localsubnet"
                    ],
                    explanation: "Permite SMB solo desde la red local."
                }
            ]
        },
        verification: [
            "nmap --script smb2-security-mode -p 445 {TARGET} — Debe mostrar 'signing required'",
            "nmap -p 445 {TARGET} desde red externa — Debe mostrar 'filtered'"
        ]
    },

    smb_signing: {
        keywords: ["signing disabled", "signing enabled but not required", "firma smb", "smb signing"],
        priority: "alta",
        title: "Activar firma SMB obligatoria",
        risk_of_change: "Clientes SMB antiguos que no soportan firma podrian perder conectividad.",
        steps: {
            linux: [
                {
                    action: "Configurar firma obligatoria en Samba",
                    commands: [
                        "sudo sed -i '/\\[global\\]/a server signing = mandatory' /etc/samba/smb.conf",
                        "sudo sed -i '/\\[global\\]/a client signing = mandatory' /etc/samba/smb.conf",
                        "sudo systemctl restart smbd"
                    ],
                    explanation: "Fuerza la firma digital en todas las comunicaciones SMB."
                }
            ],
            windows: [
                {
                    action: "Activar firma SMB via PowerShell",
                    commands: [
                        "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force",
                        "Set-SmbClientConfiguration -RequireSecuritySignature $true -Force"
                    ],
                    explanation: "Activa firma obligatoria tanto en servidor como en cliente."
                }
            ]
        },
        verification: [
            "nmap --script smb2-security-mode -p 445 {TARGET} — Debe mostrar 'message signing enabled and required'"
        ]
    },

    weak_credentials: {
        keywords: ["credencial", "contrasena debil", "weak password", "hydra", "brute", "password found", "credenciales debiles"],
        priority: "critica",
        title: "Cambiar credenciales comprometidas y aplicar politicas",
        risk_of_change: "Los usuarios afectados deberan cambiar sus contrasenas.",
        steps: {
            linux: [
                {
                    action: "Forzar cambio de contrasena de usuarios comprometidos",
                    commands: [
                        "sudo passwd -e {USUARIO}",
                        "sudo chage -d 0 {USUARIO}"
                    ],
                    explanation: "Obliga al usuario a cambiar su contrasena en el proximo inicio de sesion."
                },
                {
                    action: "Configurar politica de contrasenas robustas",
                    commands: [
                        "sudo apt install libpam-pwquality -y 2>/dev/null",
                        "echo 'minlen = 12' | sudo tee -a /etc/security/pwquality.conf",
                        "echo 'minclass = 3' | sudo tee -a /etc/security/pwquality.conf",
                        "echo 'maxrepeat = 2' | sudo tee -a /etc/security/pwquality.conf"
                    ],
                    explanation: "Exige contrasenas de minimo 12 caracteres con mayusculas, numeros y simbolos."
                },
                {
                    action: "Configurar bloqueo por intentos fallidos",
                    commands: [
                        "echo 'auth required pam_faillock.so deny=5 unlock_time=900' | sudo tee -a /etc/pam.d/common-auth"
                    ],
                    explanation: "Bloquea la cuenta por 15 minutos despues de 5 intentos fallidos."
                },
                {
                    action: "Instalar y configurar fail2ban",
                    commands: [
                        "sudo apt install fail2ban -y 2>/dev/null || sudo yum install fail2ban -y 2>/dev/null",
                        "sudo systemctl enable fail2ban --now"
                    ],
                    explanation: "Monitorea logs y bloquea IPs que intentan ataques de fuerza bruta."
                }
            ],
            windows: [
                {
                    action: "Forzar cambio de contrasena",
                    commands: [
                        "net user {USUARIO} /logonpasswordchg:yes"
                    ],
                    explanation: "El usuario debera cambiar su contrasena al iniciar sesion."
                },
                {
                    action: "Configurar politica de contrasenas via GPO",
                    commands: [
                        "net accounts /minpwlen:12 /maxpwage:90 /minpwage:1 /uniquepw:5 /lockoutthreshold:5"
                    ],
                    explanation: "Minimo 12 caracteres, cambio cada 90 dias, bloqueo tras 5 intentos."
                }
            ]
        },
        verification: [
            "hydra -l {USUARIO} -P /usr/share/wordlists/rockyou.txt {TARGET} {SERVICIO} — No debe encontrar la contrasena nueva",
            "Intentar login 6 veces con contrasena incorrecta — La cuenta debe bloquearse"
        ]
    },

    rdp_exposed: {
        keywords: ["rdp expuesto", "rdp exposed", "3389/tcp", "remote desktop"],
        priority: "critica",
        title: "Proteger acceso RDP",
        risk_of_change: "El acceso remoto funcionara solo a traves de VPN.",
        steps: {
            windows: [
                {
                    action: "Habilitar NLA (Network Level Authentication)",
                    commands: [
                        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1"
                    ],
                    explanation: "Requiere autenticacion antes de establecer la conexion RDP."
                },
                {
                    action: "Restringir RDP solo a red interna",
                    commands: [
                        "netsh advfirewall firewall set rule name=\"Remote Desktop\" new remoteip=localsubnet"
                    ],
                    explanation: "Solo permite RDP desde la red local."
                },
                {
                    action: "Cambiar puerto RDP por defecto",
                    commands: [
                        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'PortNumber' -Value 33890",
                        "Restart-Service TermService -Force"
                    ],
                    explanation: "Cambia el puerto del 3389 estandar a uno menos predecible."
                }
            ],
            linux: [
                {
                    action: "Bloquear puerto RDP si no se usa",
                    commands: [
                        "sudo ufw deny 3389/tcp",
                        "sudo ufw reload"
                    ],
                    explanation: "Si el equipo Linux no necesita RDP, bloquear el puerto."
                }
            ]
        },
        verification: [
            "nmap -p 3389 {TARGET} desde internet — Debe mostrar 'filtered'",
            "Verificar NLA habilitado en configuracion de escritorio remoto"
        ]
    },

    mysql_exposed: {
        keywords: ["mysql expuesto", "mysql exposed", "3306/tcp", "mysql"],
        priority: "critica",
        title: "Restringir acceso a MySQL",
        risk_of_change: "Las aplicaciones que conectan remotamente necesitaran ajustar su configuracion.",
        steps: {
            linux: [
                {
                    action: "Restringir MySQL a conexiones locales",
                    commands: [
                        "sudo sed -i 's/bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/mysql.conf.d/mysqld.cnf",
                        "sudo systemctl restart mysql"
                    ],
                    explanation: "MySQL solo aceptara conexiones desde el mismo servidor."
                },
                {
                    action: "Eliminar usuarios con acceso remoto no autorizado",
                    commands: [
                        "mysql -u root -p -e \"SELECT User, Host FROM mysql.user WHERE Host != 'localhost';\"",
                        "mysql -u root -p -e \"DROP USER IF EXISTS 'usuario'@'%';\"",
                        "mysql -u root -p -e \"FLUSH PRIVILEGES;\""
                    ],
                    explanation: "Revisa y elimina cuentas que permiten acceso desde cualquier IP."
                },
                {
                    action: "Bloquear puerto 3306 en firewall",
                    commands: [
                        "sudo ufw deny 3306/tcp",
                        "sudo ufw reload"
                    ],
                    explanation: "Doble proteccion: firewall + configuracion de MySQL."
                }
            ],
            windows: [
                {
                    action: "Modificar my.ini para restringir acceso",
                    commands: [
                        "echo bind-address=127.0.0.1 >> \"C:\\ProgramData\\MySQL\\MySQL Server 8.0\\my.ini\"",
                        "net stop MySQL80 && net start MySQL80"
                    ],
                    explanation: "Restringe MySQL a conexiones locales en Windows."
                }
            ]
        },
        verification: [
            "nmap -p 3306 {TARGET} desde red externa — Debe mostrar 'filtered'",
            "mysql -h {TARGET} -u root — Debe rechazar la conexion remota"
        ]
    },

    redis_exposed: {
        keywords: ["redis expuesto", "redis exposed", "6379/tcp", "redis"],
        priority: "critica",
        title: "Asegurar Redis",
        risk_of_change: "Las aplicaciones deben actualizar su configuracion para incluir la contrasena.",
        steps: {
            linux: [
                {
                    action: "Configurar contrasena y restringir acceso",
                    commands: [
                        "sudo sed -i 's/# requirepass.*/requirepass ContraseñaSegura2026!/' /etc/redis/redis.conf",
                        "sudo sed -i 's/bind .*/bind 127.0.0.1 ::1/' /etc/redis/redis.conf",
                        "sudo sed -i 's/# rename-command FLUSHALL.*/rename-command FLUSHALL \"\"/' /etc/redis/redis.conf",
                        "sudo sed -i 's/# rename-command CONFIG.*/rename-command CONFIG \"\"/' /etc/redis/redis.conf",
                        "sudo systemctl restart redis"
                    ],
                    explanation: "Agrega contrasena, restringe a localhost y deshabilita comandos peligrosos."
                },
                {
                    action: "Bloquear puerto 6379",
                    commands: [
                        "sudo ufw deny 6379/tcp",
                        "sudo ufw reload"
                    ],
                    explanation: "Cierra el puerto Redis externamente."
                }
            ]
        },
        verification: [
            "redis-cli -h {TARGET} PING — Debe pedir autenticacion",
            "nmap -p 6379 {TARGET} desde red externa — Debe mostrar 'filtered'"
        ]
    },

    open_ports_general: {
        keywords: ["superficie de exposicion", "puertos abiertos", "network exposure", "puertos innecesarios"],
        priority: "media",
        title: "Cerrar puertos innecesarios con firewall",
        risk_of_change: "Servicios no esenciales dejaran de ser accesibles externamente.",
        steps: {
            linux: [
                {
                    action: "Activar firewall y politica por defecto: denegar",
                    commands: [
                        "sudo ufw default deny incoming",
                        "sudo ufw default allow outgoing",
                        "sudo ufw enable"
                    ],
                    explanation: "Bloquea todo el trafico entrante excepto lo que se permita explicitamente."
                },
                {
                    action: "Permitir solo los puertos necesarios",
                    commands: [
                        "sudo ufw allow 22/tcp comment 'SSH'",
                        "sudo ufw allow 80/tcp comment 'HTTP'",
                        "sudo ufw allow 443/tcp comment 'HTTPS'",
                        "sudo ufw reload",
                        "sudo ufw status verbose"
                    ],
                    explanation: "Solo abre los puertos que tu organizacion necesita. Ajusta segun tus servicios."
                }
            ],
            windows: [
                {
                    action: "Configurar Windows Firewall con perfil restrictivo",
                    commands: [
                        "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound",
                        "netsh advfirewall firewall add rule name=\"Allow SSH\" dir=in action=allow protocol=tcp localport=22",
                        "netsh advfirewall firewall add rule name=\"Allow HTTPS\" dir=in action=allow protocol=tcp localport=443"
                    ],
                    explanation: "Bloquea todo entrante y solo permite puertos especificos."
                }
            ]
        },
        verification: [
            "nmap -p- {TARGET} — Solo debe mostrar los puertos permitidos como 'open'",
            "sudo ufw status verbose — Verificar las reglas activas"
        ]
    },

    http_no_https: {
        keywords: ["http sin https", "sin cifrado web", "80/tcp", "http expuesto"],
        priority: "alta",
        title: "Implementar HTTPS con certificado SSL/TLS",
        risk_of_change: "Minimo — redirecciona trafico HTTP a HTTPS automaticamente.",
        steps: {
            linux: [
                {
                    action: "Instalar Certbot para certificado gratuito Let's Encrypt",
                    commands: [
                        "sudo apt install certbot python3-certbot-nginx -y 2>/dev/null || sudo apt install certbot python3-certbot-apache -y 2>/dev/null",
                        "sudo certbot --nginx -d tudominio.com --agree-tos --non-interactive"
                    ],
                    explanation: "Obtiene e instala un certificado SSL gratuito automaticamente."
                },
                {
                    action: "Configurar redireccion HTTP a HTTPS",
                    commands: [
                        "# En nginx: agregar al server block del puerto 80:",
                        "# return 301 https://$server_name$request_uri;",
                        "sudo systemctl restart nginx"
                    ],
                    explanation: "Todo el trafico HTTP se redirige automaticamente a HTTPS."
                },
                {
                    action: "Configurar renovacion automatica",
                    commands: [
                        "echo '0 3 * * * root certbot renew --quiet' | sudo tee /etc/cron.d/certbot-renew"
                    ],
                    explanation: "Renueva el certificado automaticamente cada 3 meses."
                }
            ]
        },
        verification: [
            "curl -I https://tudominio.com — Debe responder con certificado valido",
            "curl -I http://tudominio.com — Debe redirigir a https (301)"
        ]
    }
};

/* ═══════════════════════════════════════════════════
   GENERADOR DE PLAN DE REMEDIACION
   ═══════════════════════════════════════════════════ */

function detectOSFromScanData(scanPayload) {
    const osName = toLower(
        scanPayload?.os_detection?.name ||
        scanPayload?.os_detection?.osmatch?.[0]?.name ||
        ""
    );

    if (osName.includes("windows")) return "windows";
    if (osName.includes("linux") || osName.includes("ubuntu") || osName.includes("debian") ||
        osName.includes("centos") || osName.includes("redhat") || osName.includes("fedora") ||
        osName.includes("unix")) return "linux";

    const services = (scanPayload?.ports || []).map((p) => toLower(p?.service || "")).join(" ");
    if (services.includes("microsoft") || services.includes("windows")) return "windows";

    return "linux";
}

function matchPlaybookForVulnerability(vulnerability) {
    const titleLower = toLower(vulnerability?.title);
    const descLower = toLower(vulnerability?.description);
    const scriptId = toLower(vulnerability?.script_id || "");
    const combined = `${titleLower} ${descLower} ${scriptId}`;

    for (const [key, playbook] of Object.entries(REMEDIATION_PLAYBOOKS)) {
        for (const keyword of playbook.keywords) {
            if (combined.includes(keyword)) {
                return { key, playbook };
            }
        }
    }
    return null;
}

function generateRemediationPlan(scanPayload, analysisResult) {
    const target = scanPayload?.host || scanPayload?.target || "objetivo";
    const detectedOS = detectOSFromScanData(scanPayload);
    const vulnerabilities = analysisResult?.vulnerabilities || [];
    const credentialTests = scanPayload?.credential_tests || [];

    const credentialFindings = credentialTests.filter((t) =>
        toLower(t?.status) === "found" || toLower(t?.status) === "success"
    );

    const matchedPlaybooks = new Map();
    const priorityOrder = { critica: 0, alta: 1, media: 2, baja: 3 };

    for (const vuln of vulnerabilities) {
        const match = matchPlaybookForVulnerability(vuln);
        if (match && !matchedPlaybooks.has(match.key)) {
            matchedPlaybooks.set(match.key, {
                playbook: match.playbook,
                triggeredBy: vuln.title || "Hallazgo detectado",
                severity: vuln.severity || "medium"
            });
        }
    }

    if (credentialFindings.length > 0 && !matchedPlaybooks.has("weak_credentials")) {
        matchedPlaybooks.set("weak_credentials", {
            playbook: REMEDIATION_PLAYBOOKS.weak_credentials,
            triggeredBy: `${credentialFindings.length} credencial(es) comprometida(s)`,
            severity: "critical"
        });
    }

    const openPorts = (scanPayload?.ports || []).filter((p) => toLower(p?.state) === "open");
    if (openPorts.length > 3 && !matchedPlaybooks.has("open_ports_general")) {
        matchedPlaybooks.set("open_ports_general", {
            playbook: REMEDIATION_PLAYBOOKS.open_ports_general,
            triggeredBy: `${openPorts.length} puertos abiertos detectados`,
            severity: "medium"
        });
    }

    const remediationItems = Array.from(matchedPlaybooks.values())
        .sort((a, b) => (priorityOrder[a.playbook.priority] ?? 3) - (priorityOrder[b.playbook.priority] ?? 3));

    const plan = {
        target,
        detected_os: detectedOS,
        generated_at: new Date().toISOString(),
        total_actions: remediationItems.length,
        risk_score: analysisResult?.overall_risk_score ?? analysisResult?.risk_score ?? null,
        summary: remediationItems.length > 0
            ? `Se generaron ${remediationItems.length} planes de accion para resolver los problemas detectados en ${target} (${detectedOS.toUpperCase()}).`
            : `No se encontraron vulnerabilidades conocidas con playbooks de remediacion automatica para ${target}.`,
        actions: remediationItems.map((item, index) => {
            const steps = item.playbook.steps[detectedOS] || item.playbook.steps.linux || [];
            return {
                order: index + 1,
                priority: item.playbook.priority,
                title: item.playbook.title,
                triggered_by: item.triggeredBy,
                risk_of_change: item.playbook.risk_of_change,
                steps: steps.map((step) => ({
                    action: step.action,
                    commands: step.commands.map((cmd) => cmd.replace(/\{TARGET\}/g, target)),
                    explanation: step.explanation
                })),
                verification: (item.playbook.verification || []).map((v) => v.replace(/\{TARGET\}/g, target))
            };
        })
    };

    return plan;
}

function formatRemediationPlanForChat(plan) {
    if (!plan || plan.total_actions === 0) {
        return "No se encontraron vulnerabilidades con planes de remediacion automatica. El sistema parece estar en buen estado.";
    }

    const lines = [
        `PLAN DE REMEDIACION — ${plan.target} (${plan.detected_os.toUpperCase()})`,
        `Se requieren ${plan.total_actions} acciones correctivas:`,
        ""
    ];

    for (const action of plan.actions) {
        lines.push(`${"=".repeat(50)}`);
        lines.push(`[${action.priority.toUpperCase()}] ${action.order}. ${action.title}`);
        lines.push(`Detectado por: ${action.triggered_by}`);
        lines.push(`Riesgo del cambio: ${action.risk_of_change}`);
        lines.push("");

        for (const step of action.steps) {
            lines.push(`  >> ${step.action}`);
            lines.push(`     ${step.explanation}`);
            lines.push("");
            for (const cmd of step.commands) {
                lines.push(`     $ ${cmd}`);
            }
            lines.push("");
        }

        if (action.verification.length > 0) {
            lines.push("  Verificacion:");
            for (const v of action.verification) {
                lines.push(`    - ${v}`);
            }
        }
        lines.push("");
    }

    lines.push(`${"=".repeat(50)}`);
    lines.push("IMPORTANTE: Ejecute los comandos en un entorno de prueba antes de aplicar en produccion.");
    lines.push("Haga un backup completo antes de realizar cambios.");

    return lines.join("\n");
}

function buildLocalHeuristicAnalysis(rawScanData) {
    const scanPayload = extractScanPayloadFromSimulation({ json_response: rawScanData }) ||
        (rawScanData && typeof rawScanData === "object" ? rawScanData : {});

    const networkInfo = scanPayload?.network_info && typeof scanPayload.network_info === "object"
        ? scanPayload.network_info
        : {};

    const ports = Array.isArray(scanPayload?.ports) ? scanPayload.ports : [];
    const openPorts = ports.filter((port) => {
        const state = toLower(port?.state || "open");
        return !state || state === "open";
    });

    const vulnerabilitiesRaw = Array.isArray(scanPayload?.vulnerabilities) ? scanPayload.vulnerabilities : [];
    const credentialTests = Array.isArray(scanPayload?.credential_tests) ? scanPayload.credential_tests : [];

    const credentialFindings = credentialTests.filter(
        (item) => toLower(item?.status) === "credentials_found"
    );

    const host = scanPayload?.host || networkInfo?.host_ip || "objetivo-no-especificado";

    const normalizedVulnerabilities = vulnerabilitiesRaw.map((vulnerability, index) => ({
        title:
            // vulnerability?.title ||
            // vulnerability?.script_id ||
            // vulnerability?.affected_service ||
            `Vulnerabilidad ${index + 1}`,
        script_id: vulnerability?.script_id || null,
        severity: normalizeSeverity(vulnerability?.severity),
        description: vulnerability?.description || vulnerability?.output || "Hallazgo sin detalle adicional.",
        impact:
            // vulnerability?.impact ||
            "Puede comprometer confidencialidad, integridad o disponibilidad del activo escaneado.",
        affected_component:
            vulnerability?.affected_component || vulnerability?.affected_service || "Servicio/host objetivo",
        cve_id: vulnerability?.cve_id || "N/A"
    }));

    const mergedVulnerabilities = [...normalizedVulnerabilities];
    const vulnerabilityKeys = new Set(
        normalizedVulnerabilities.map((item) => `${toLower(item.title)}|${toLower(item.affected_component)}`)
    );

    const actions = new Set();
    const insecureProtocols = new Set();
    const servicesDetected = new Set(
        (Array.isArray(networkInfo?.services_detected) ? networkInfo.services_detected : [])
            .map((service) => String(service || "").trim())
            .filter(Boolean)
    );

    let riskScore = 0;

    riskScore += Math.min(openPorts.length * 0.45, 2.5);

    const riskyPortRules = {
        21: {
            title: "FTP expuesto sin cifrado",
            severity: "high",
            score: 1.0,
            action: "Deshabilitar FTP o migrar a SFTP/FTPS con cifrado y credenciales robustas."
        },
        23: {
            title: "Telnet expuesto",
            severity: "critical",
            score: 1.8,
            action: "Deshabilitar Telnet y migrar acceso remoto a SSH con autenticacion por llave."
        },
        445: {
            title: "SMB expuesto",
            severity: "high",
            score: 1.2,
            action: "Restringir SMB por segmentacion de red y aplicar hardening de comparticiones."
        },
        3389: {
            title: "RDP expuesto",
            severity: "high",
            score: 1.0,
            action: "Restringir RDP por VPN/ACL, aplicar MFA y politicas de bloqueo."
        },
        3306: {
            title: "MySQL expuesto",
            severity: "medium",
            score: 0.8,
            action: "Restringir MySQL a red privada y aplicar minimo privilegio."
        },
        5432: {
            title: "PostgreSQL expuesto",
            severity: "medium",
            score: 0.8,
            action: "Restringir PostgreSQL a red privada y reforzar autenticacion."
        },
        6379: {
            title: "Redis expuesto",
            severity: "high",
            score: 1.0,
            action: "Deshabilitar acceso publico a Redis y aplicar autenticacion/ACL."
        }
    };

    for (const port of openPorts) {
        const portNumber = parsePositiveInt(port?.port);
        const serviceName = String(port?.service || port?.product || "").trim();
        const serviceLower = toLower(serviceName);

        if (serviceName) {
            servicesDetected.add(serviceName);
        }

        if (serviceLower.includes("telnet") || portNumber === 23) {
            insecureProtocols.add("telnet");
        }

        if (serviceLower.includes("ftp") || portNumber === 21) {
            insecureProtocols.add("ftp");
        }

        if (serviceLower.includes("smb") || serviceLower.includes("netbios") || portNumber === 445) {
            insecureProtocols.add("smb");
        }

        const rule = portNumber ? riskyPortRules[portNumber] : null;

        if (rule) {
            riskScore += rule.score;
            actions.add(rule.action);

            const vulnerability = {
                title: rule.title,
                script_id: null,
                severity: rule.severity,
                description: `Servicio expuesto en puerto ${portNumber}/${port?.protocol || "tcp"}.`,
                impact: "Incrementa superficie de ataque y facilita explotacion remota si no hay controles compensatorios.",
                affected_component: `${portNumber}/${port?.protocol || "tcp"} ${serviceName}`.trim(),
                cve_id: "N/A"
            };

            const key = `${toLower(vulnerability.title)}|${toLower(vulnerability.affected_component)}`;
            if (!vulnerabilityKeys.has(key)) {
                vulnerabilityKeys.add(key);
                mergedVulnerabilities.push(vulnerability);
            }
        }

        const scripts = Array.isArray(port?.scripts) ? port.scripts : [];
        for (const script of scripts) {
            const scriptId = toLower(script?.id);
            const scriptOutput = toLower(script?.output);

            if (scriptId === "ftp-anon" && scriptOutput.includes("anonymous ftp login allowed")) {
                riskScore += 1.2;
                actions.add("Deshabilitar login anonimo en FTP y limitar acceso con credenciales unicas.");

                const vulnerability = {
                    title: "FTP anonimo habilitado",
                    script_id: script?.id || "ftp-anon",
                    severity: "high",
                    description: "Se detecto acceso anonimo en servicio FTP.",
                    impact: "Permite acceso no autenticado y facilita exfiltracion o enumeracion de archivos.",
                    affected_component: `${port?.port || "21"}/${port?.protocol || "tcp"} ftp`,
                    cve_id: "N/A"
                };

                const key = `${toLower(vulnerability.title)}|${toLower(vulnerability.affected_component)}`;
                if (!vulnerabilityKeys.has(key)) {
                    vulnerabilityKeys.add(key);
                    mergedVulnerabilities.push(vulnerability);
                }
            }
        }
    }

    for (const finding of credentialFindings) {
        riskScore += 1.5;

        const portText = String(finding?.port || "?");
        const serviceText = String(finding?.service || "servicio");

        actions.add("Rotar credenciales comprometidas, aplicar MFA y politicas anti-bruteforce.");

        const vulnerability = {
            title: `Credenciales debiles detectadas en ${serviceText}`,
            script_id: "hydra-credentials",
            severity: "critical",
            description: `Se encontraron credenciales validas o reutilizables en ${serviceText} (${portText}).`,
            impact: "Permite acceso no autorizado al servicio y movimiento lateral.",
            affected_component: `${portText} ${serviceText}`,
            cve_id: "N/A"
        };

        const key = `${toLower(vulnerability.title)}|${toLower(vulnerability.affected_component)}`;
        if (!vulnerabilityKeys.has(key)) {
            vulnerabilityKeys.add(key);
            mergedVulnerabilities.push(vulnerability);
        }
    }

    const controlSignals = credentialTests.filter((item) => {
        const status = toLower(item?.status);
        return status === "lockout_detected" || status === "rate_limited";
    });

    if (controlSignals.length > 0) {
        riskScore += 0.3;
        actions.add("Revisar eventos de lockout/rate-limit para ajustar telemetria y controles de deteccion temprana.");
    }

    const vulnerabilityScore = mergedVulnerabilities.reduce(
        (total, vulnerability) => total + severityWeight(vulnerability?.severity),
        0
    );

    riskScore += Math.min(vulnerabilityScore, 4.8);

    if (openPorts.length > 0) {
        actions.add("Cerrar puertos y servicios no esenciales antes de exponer el activo en produccion.");
    }

    if (mergedVulnerabilities.length > 0) {
        actions.add("Aplicar parcheo y hardening priorizando hallazgos criticos/altos.");
    }

    if (actions.size === 0) {
        actions.add("Mantener hardening continuo, monitoreo y revisiones periodicas de exposicion de red.");
    }

    if (mergedVulnerabilities.length === 0 && openPorts.length > 0) {
        mergedVulnerabilities.push({
            title: "Superficie de exposicion de red",
            script_id: null,
            severity: "medium",
            description: "No se reportaron vulnerabilidades explicitas, pero hay puertos abiertos accesibles.",
            impact: "Aumenta superficie de ataque y requiere validacion manual de hardening.",
            affected_component: host,
            cve_id: "N/A"
        });
    }

    riskScore = Math.max(0, Math.min(10, Math.round(riskScore * 10) / 10));

    const riskLevel = riskLevelFromScore(riskScore);
    const immediateActions = Array.from(actions).slice(0, 8);

    const confidenceRaw = 0.45 + (mergedVulnerabilities.length * 0.02) + (credentialFindings.length * 0.06);
    const confidence = Math.max(0.35, Math.min(0.9, confidenceRaw));

    const generatedAt = new Date().toISOString();

    const summary =
        `Analisis local heuristico completado para ${host}. ` +
        `Puertos abiertos: ${openPorts.length}. ` +
        `Hallazgos relevantes: ${mergedVulnerabilities.length}. ` +
        `Alertas de credenciales: ${credentialFindings.length}. ` +
        `Riesgo estimado: ${riskLevel} (${riskScore}/10).`;

    return {
        executive_summary: summary,
        overall_risk_score: riskScore,
        risk_level: riskLevel,
        scan_metadata: {
            host,
            scan_profile: scanPayload?.scan_profile || null,
            analyzer: "local_heuristic",
            open_ports_count: openPorts.length,
            vulnerabilities_count: mergedVulnerabilities.length,
            credential_findings_count: credentialFindings.length,
            generated_at: generatedAt
        },
        vulnerabilities: mergedVulnerabilities.slice(0, 20),
        network_exposure: {
            open_ports_count: openPorts.length,
            services_exposed: Array.from(servicesDetected),
            insecure_protocols: Array.from(insecureProtocols),
            target: host
        },
        compliance_notes: {
            note: "Analisis local generado sin OpenAI. Validar manualmente para cierre formal."
        },
        immediate_actions: immediateActions,
        recommendations: immediateActions,
        analysis_confidence: Number(confidence.toFixed(2)),
        generated_at: generatedAt,
        model_version: "local-heuristic-v1",
        fallback_mode: true
    };
}

async function analyzeSimulationWithFallback(rawScanData) {
    if (!isOpenAIConfigured()) {
        return {
            analysis: buildLocalHeuristicAnalysis(rawScanData),
            fallbackMode: true,
            source: "local"
        };
    }

    try {
        const analysis = await analyzeWithAI(rawScanData);
        return {
            analysis,
            fallbackMode: false,
            source: "openai"
        };
    } catch (error) {
        if (error.message.includes("not configured") || error.message.includes("package is missing")) {
            return {
                analysis: buildLocalHeuristicAnalysis(rawScanData),
                fallbackMode: true,
                source: "local"
            };
        }

        throw error;
    }
}

function buildOfflineRemediationSteps(simulationContext) {
    if (!simulationContext || typeof simulationContext !== "object") {
        return [
            "Cierra puertos no necesarios con firewall y aplica principio de minimo privilegio.",
            "Actualiza servicios expuestos y desactiva protocolos inseguros (Telnet/FTP).",
            "Aplica MFA y rotacion de credenciales para accesos administrativos."
        ];
    }

    const services = Array.isArray(simulationContext.services)
        ? simulationContext.services.map((item) => String(item).toLowerCase()).join(" ")
        : "";

    const steps = [];

    if (services.includes("23/tcp") || services.includes("telnet")) {
        steps.push("Deshabilita Telnet y migra acceso remoto a SSH con autenticacion por llave.");
    }

    if (services.includes("21/tcp") || services.includes("ftp")) {
        steps.push("Deshabilita FTP sin cifrado o migra a SFTP/FTPS con credenciales robustas.");
    }

    if (services.includes("445/tcp") || services.includes("smb")) {
        steps.push("Restringe SMB por red, bloquea acceso externo y aplica parches de seguridad.");
    }

    if ((simulationContext.credential_alerts_count || 0) > 0) {
        steps.push("Hubo credenciales expuestas: forza cambio inmediato de contrasenas y activa politicas anti-bruteforce.");
    }

    if ((simulationContext.open_ports_count || 0) > 0) {
        steps.push("Revisa cada puerto abierto y elimina servicios no esenciales antes de pasar a produccion.");
    }

    if (steps.length === 0) {
        steps.push("Mantener hardening continuo: parcheo, segmentacion de red y monitoreo de logs de autenticacion.");
    }

    return steps.slice(0, 4);
}

function buildFAQReply(message, simulationContext) {
    const normalized = String(message || "").toLowerCase().trim();

    if (!normalized) {
        return null;
    }

    const contextLine = simulationContext
        ? "Contexto activo: simulacion #" + simulationContext.id + " sobre " + (simulationContext.target_ip || "objetivo no especificado") + "."
        : "No hay simulacion activa; puedes usar 'historial' para cargar contexto.";

    if (/faq|preguntas frecuentes|que puedes hacer|como funciona horus|que hace horus/.test(normalized)) {
        return [
            "FAQ HORUS (resumen rapido):",
            "1) Descubrir red: identifica hosts activos en una subred (CIDR).",
            "2) Escaneo profundo: evalua puertos/servicios y pruebas de credenciales (Hydra).",
            "3) Monitor unificado: muestra riesgo, findings y correlaciones anti-ransomware.",
            "4) Remediacion: PREVIEW muestra plan; EJECUTAR aplica contencion/remediacion.",
            "5) Reporte ejecutivo: descargar/enviar PDF de simulaciones guardadas.",
            contextLine
        ].join("\n");
    }

    if (/diferencia|descubrir red|escaneo profundo|discover|deep scan/.test(normalized)) {
        return [
            "Diferencia entre modos:",
            "- Descubrir red: barrido de subred para encontrar equipos activos.",
            "- Escaneo profundo: analisis de un host especifico con puertos, servicios y pruebas de credenciales.",
            "Flujo recomendado: primero descubrir red, luego escaneo profundo por host critico."
        ].join("\n");
    }

    if (/remediacion|remediation|preview|ejecutar|queued|cola|auto_remediation|no pudo corregir/.test(normalized)) {
        return [
            "Remediacion en HORUS:",
            "- PREVIEW: muestra que comandos/acciones aplicaria la herramienta.",
            "- EJECUTAR: aplica la remediacion en modo controlado.",
            "- Si aparece 'queued', revisa permisos del playbook y confirmacion de ejecucion.",
            "- Cada accion queda auditada en BACKEND/ai-orchestrator/engine/remediation_audit.log para trazabilidad."
        ].join("\n");
    }

    if (/openai|api key|configurar ia|ia no configurado|modelo gpt/.test(normalized)) {
        return [
            "Configuracion OpenAI:",
            "1) Edita /Users/user/Desktop/HORUS/BACKEND/api/.env",
            "2) Define OPENAI_API_KEY=<tu_clave_real>",
            "3) Reinicia Node API (cd BACKEND/api && node server.js o npm run dev)",
            "4) En el chat ejecuta 'estado ia' para verificar que aparezca 'OpenAI activo'.",
            "Nota: sin clave real, HORUS usa modo local (fallback)."
        ].join("\n");
    }

    if (/reporte|pdf|correo|enviar reporte|descargar reporte/.test(normalized)) {
        return [
            "Reportes ejecutivos:",
            "- Descargar: 'descargar reporte ejecutivo ultima' o 'descargar reporte ejecutivo 12'.",
            "- Enviar por correo: 'enviar reporte ejecutivo ultima a correo@dominio.com'.",
            "- Si hubo remediacion ejecutada, el PDF prioriza la explicacion del blindaje aplicado por HORUS."
        ].join("\n");
    }

    if (/credenciales|admin|login|iniciar sesion/.test(normalized)) {
        return [
            "Acceso y cuentas:",
            "- Usuario admin por defecto: admin",
            "- Contrasena por defecto: horus2026 (si no fue cambiada)",
            "- Si falla login con error de base de datos, valida DB_HOST/DB_PORT/DB_USER/DB_PASSWORD en BACKEND/api/.env."
        ].join("\n");
    }

    return null;
}

function buildOfflineChatReply(message, simulationContext, scanPayload, analysisResult) {
    const normalized = String(message || "").toLowerCase();
    const lines = [
        "Soy HORUS IA en modo asistente local (OpenAI no configurado)."
    ];

    if (simulationContext) {
        lines.push(
            [
                `Contexto activo: simulacion #${simulationContext.id}.`,
                `Puertos abiertos: ${simulationContext.open_ports_count ?? 0}.`,
                `Alertas de credenciales: ${simulationContext.credential_alerts_count ?? 0}.`,
                `Hallazgos de vulnerabilidades: ${simulationContext.vulnerabilities_count ?? 0}.`
            ].join(" ")
        );
    } else {
        lines.push("No tengo contexto de simulacion cargado. Usa \"historial\" para ver IDs y trabajar sobre una simulacion.");
    }

    if (/reporte|pdf|documento|ejecutivo|descargar/.test(normalized)) {
        lines.push(
            "Para descargar el documento ejecutivo: \"descargar reporte ejecutivo ultima\" o \"descargar reporte ejecutivo 12\"."
        );
    }

    if (/correo|email|mail|enviar/.test(normalized)) {
        lines.push(
            "Para enviarlo por correo: \"enviar reporte ejecutivo ultima a tu-correo@dominio.com\"."
        );
    }

    if (/correg|corrig|corrij|remedi|mitig|hardening|solucion|resolver|arreglar|fixear|fix|como soluciono/.test(normalized)) {
        if (scanPayload && analysisResult) {
            const plan = generateRemediationPlan(scanPayload, analysisResult);
            lines.push(formatRemediationPlanForChat(plan));
        } else if (simulationContext) {
            const steps = buildOfflineRemediationSteps(simulationContext).map((step, index) => `${index + 1}. ${step}`);
            lines.push(`Acciones recomendadas:\n${steps.join("\n")}`);
            lines.push("Para un plan detallado con comandos especificos, usa el boton \"Resolver problemas\" o escribe \"resolver problemas\".");
        } else {
            lines.push("Necesito contexto de una simulacion para generar un plan de remediacion. Usa \"historial\" para seleccionar una simulacion.");
        }
    }

    return lines.join("\n\n");
}

async function buildPdfReportPayload(simulationId) {
    if (!isPersistenceEnabled()) {
        throw makeControllerError(503, "Database persistence is disabled");
    }

    const simulation = await getSimulationById(simulationId);

    if (!simulation) {
        throw makeControllerError(404, "Simulation not found");
    }

    const rawAnalysis = extractStoredAiAnalysis(simulation);
    if (!rawAnalysis) {
        throw makeControllerError(404, "No stored AI analysis for this simulation. Run /api/ai/analyze/simulation/:id first.");
    }

    const scanPayload = extractScanPayloadFromSimulation(simulation);

    const remediationActivity = loadRecentRemediationActivity({
        target: simulation.target_ip || scanPayload?.host || null,
        limit: 8
    });

    const normalizedReport = normalizeAnalysisForPdf(rawAnalysis, simulationId, remediationActivity);
    if (!normalizedReport) {
        throw makeControllerError(422, "Stored AI analysis format is invalid");
    }

    const validation = validateReportData(normalizedReport);
    if (!validation.valid) {
        throw makeControllerError(422, "Stored AI analysis does not meet PDF schema", validation.error);
    }

    const simulationMeta = {
        target: simulation.target_ip || scanPayload?.host || "Objetivo no especificado",
        scan_date: simulation.created_at || new Date().toISOString(),
        project_name: "HORUS Security Assessment"
    };

    const pdfBuffer = await generatePDFReport(normalizedReport, simulationMeta);

    return {
        simulation,
        simulationMeta,
        normalizedReport,
        pdfBuffer
    };
}

async function persistAnalysis(simulationId, userId, analysis) {
    if (!simulationId) {
        return {
            enabled: false,
            stored: false,
            reason: "simulation_id not provided"
        };
    }

    if (!isPersistenceEnabled()) {
        return {
            enabled: false,
            stored: false,
            reason: "DB persistence disabled"
        };
    }

    try {
        await saveAIAnalysis(simulationId, analysis, { userId });
        return {
            enabled: true,
            stored: true
        };
    } catch (error) {
        return {
            enabled: true,
            stored: false,
            error: error.message
        };
    }
}

export async function analyzeSingleSimulation(req, res) {
    try {
        const {
            simulation_id: bodySimulationId,
            simulationId: bodySimulationIdAlt,
            user_id: bodyUserId,
            userId: bodyUserIdAlt,
            persist = false,
            simulation_data: simulationDataWrapped,
            simulationData: simulationDataWrappedAlt,
            ...rawPayload
        } = req.body || {};

        const simulationData = simulationDataWrapped || simulationDataWrappedAlt || rawPayload;

        if (!simulationData || Object.keys(simulationData).length === 0) {
            return res.status(400).json({
                success: false,
                error: "Request body must contain simulation data"
            });
        }

        const { analysis, fallbackMode, source } = await analyzeSimulationWithFallback(simulationData);

        const simulationId = parsePositiveInt(bodySimulationId || bodySimulationIdAlt);
        const userId = parsePositiveInt(bodyUserId || bodyUserIdAlt || req.headers["x-user-id"]) || 1;

        const persistence = persist || simulationId
            ? await persistAnalysis(simulationId, userId, analysis)
            : {
                enabled: isPersistenceEnabled(),
                stored: false,
                reason: "Persistence not requested"
            };

        return res.status(200).json({
            success: true,
            simulation_id: simulationId,
            analysis,
            persistence,
            fallback_mode: fallbackMode,
            analysis_source: source
        });
    } catch (error) {
        if (error.message.includes("Invalid simulation data")) {
            return res.status(400).json({
                success: false,
                error: error.message
            });
        }

        return res.status(500).json({
            success: false,
            error: "Failed to analyze simulation data",
            details: error.message
        });
    }
}

export async function analyzeBatchSimulations(req, res) {
    try {
        const { simulations } = req.body || {};

        if (!Array.isArray(simulations) || simulations.length === 0) {
            return res.status(400).json({
                success: false,
                error: "Request body must contain 'simulations' array with at least one item"
            });
        }

        if (simulations.length > 10) {
            return res.status(400).json({
                success: false,
                error: "Batch analysis is limited to 10 simulations per request"
            });
        }

        const results = [];
        const errors = [];

        for (let index = 0; index < simulations.length; index += 1) {
            try {
                const { analysis, fallbackMode, source } = await analyzeSimulationWithFallback(simulations[index]);
                results.push({
                    index,
                    success: true,
                    analysis,
                    fallback_mode: fallbackMode,
                    analysis_source: source
                });
            } catch (error) {
                errors.push({
                    index,
                    success: false,
                    error: error.message
                });
            }
        }

        return res.status(200).json({
            success: true,
            batch_results: {
                total: simulations.length,
                successful: results.length,
                failed: errors.length,
                results,
                errors
            }
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            error: "Failed to perform batch analysis",
            details: error.message
        });
    }
}

export async function analyzeStoredSimulation(req, res) {
    const simulationId = parsePositiveInt(req.params.simulationId);
    if (!simulationId) {
        return res.status(400).json({
            success: false,
            error: "simulationId must be a positive integer"
        });
    }

    if (!isPersistenceEnabled()) {
        return res.status(503).json({
            success: false,
            error: "Database persistence is disabled"
        });
    }

    try {
        const simulation = await getSimulationById(simulationId);
        if (!simulation) {
            return res.status(404).json({
                success: false,
                error: "Simulation not found"
            });
        }

        const simulationPayload = extractScanPayloadFromSimulation(simulation);

        if (!simulationPayload) {
            return res.status(422).json({
                success: false,
                error: "Simulation does not include scan payload required for AI analysis"
            });
        }

        // Discovery-type simulations get a specialized analysis
        if (isDiscoveryPayload(simulationPayload)) {
            const analysis = buildDiscoveryAnalysis(simulationPayload);
            const userId = parsePositiveInt(req.body?.user_id || req.headers["x-user-id"] || simulation.user_id) || 1;
            const persistence = await persistAnalysis(simulationId, userId, analysis);

            return res.status(200).json({
                success: true,
                simulation_id: simulationId,
                analysis,
                persistence,
                fallback_mode: true,
                analysis_source: "local_discovery"
            });
        }

        const { analysis, fallbackMode, source } = await analyzeSimulationWithFallback(simulationPayload);
        const userId = parsePositiveInt(req.body?.user_id || req.headers["x-user-id"] || simulation.user_id) || 1;
        const persistence = await persistAnalysis(simulationId, userId, analysis);

        return res.status(200).json({
            success: true,
            simulation_id: simulationId,
            analysis,
            persistence,
            fallback_mode: fallbackMode,
            analysis_source: source
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            error: "Failed to analyze stored simulation",
            details: error.message
        });
    }
}

function buildChatSimulationContext(simulation) {
    const scanPayload = extractScanPayloadFromSimulation(simulation) || {};
    const ports = Array.isArray(scanPayload.ports) ? scanPayload.ports : [];
    const openPorts = ports.filter((port) => String(port?.state || "").toLowerCase() === "open");
    const vulnerabilities = Array.isArray(scanPayload.vulnerabilities) ? scanPayload.vulnerabilities : [];
    const credentialTests = Array.isArray(scanPayload.credential_tests) ? scanPayload.credential_tests : [];

    const services = openPorts
        .slice(0, 8)
        .map((port) => `${port.port}/${port.protocol || "tcp"} ${port.service || ""}`.trim());

    return {
        id: simulation.id,
        scan_type: simulation.scan_type || null,
        status: simulation.status || null,
        target_ip: simulation.target_ip || scanPayload.host || null,
        target_subnet: simulation.target_subnet || null,
        created_at: simulation.created_at || null,
        scan_time_seconds: simulation.scan_time_seconds || scanPayload.scan_time || null,
        hostname: scanPayload.hostname || null,
        os_hint: scanPayload?.os_detection?.name || null,
        open_ports_count: openPorts.length,
        vulnerabilities_count: vulnerabilities.length,
        credential_alerts_count: credentialTests.filter(
            (item) => String(item?.status || "").toLowerCase() === "credentials_found"
        ).length,
        services
    };
}

export async function chatWithAIAgent(req, res) {
    const message = String(req.body?.message || "").trim();

    if (!message) {
        return res.status(400).json({
            success: false,
            error: "message is required"
        });
    }

    const simulationId = parsePositiveInt(req.body?.simulation_id || req.body?.simulationId);
    const conversation = Array.isArray(req.body?.conversation) ? req.body.conversation : [];
    const userContext = req.body?.context && typeof req.body.context === "object" ? req.body.context : {};

    let simulationContext = null;
    let scanPayload = null;
    let analysisResult = null;

    if (simulationId && isPersistenceEnabled()) {
        try {
            const simulation = await getSimulationById(simulationId);
            if (simulation) {
                simulationContext = buildChatSimulationContext(simulation);

                const normalizedMsg = message.toLowerCase();
                if (/correg|corrig|corrij|remedi|mitig|hardening|solucion|resolver|arreglar|fix|como soluciono/.test(normalizedMsg)) {
                    scanPayload = extractScanPayloadFromSimulation(simulation) || {};
                    const storedAnalysis = extractStoredAiAnalysis(simulation);
                    if (storedAnalysis) {
                        analysisResult = storedAnalysis;
                    } else {
                        analysisResult = buildLocalHeuristicAnalysis(
                            scanPayload?.raw || simulation.json_response || scanPayload
                        );
                    }
                }
            }
        } catch {
            simulationContext = null;
        }
    }

    const mergedContext = {
        ...userContext,
        ...(simulationContext ? { simulation: simulationContext } : {})
    };

    const aiConfigured = isOpenAIConfigured();
    const faqReply = buildFAQReply(message, simulationContext);

    if (faqReply) {
        return res.status(200).json({
            success: true,
            reply: faqReply,
            model: aiConfigured ? "faq-assistant" : "local-faq",
            usage: null,
            simulation_id: simulationId || null,
            context_attached: Boolean(simulationContext),
            fallback_mode: !aiConfigured
        });
    }

    if (!aiConfigured) {
        return res.status(200).json({
            success: true,
            reply: buildOfflineChatReply(message, simulationContext, scanPayload, analysisResult),
            model: "local-heuristic",
            usage: null,
            simulation_id: simulationId || null,
            context_attached: Boolean(simulationContext),
            fallback_mode: true
        });
    }

    try {
        const chatResult = await chatWithAIAgentService({
            message,
            conversation,
            context: mergedContext
        });

        return res.status(200).json({
            success: true,
            reply: chatResult.reply,
            model: chatResult.model,
            usage: chatResult.usage || null,
            simulation_id: simulationId || null,
            context_attached: Boolean(simulationContext)
        });
    } catch (error) {
        if (error.message.includes("not configured") || error.message.includes("package is missing")) {
            return res.status(200).json({
                success: true,
                reply: buildOfflineChatReply(message, simulationContext, scanPayload, analysisResult),
                model: "local-fallback",
                usage: null,
                simulation_id: simulationId || null,
                context_attached: Boolean(simulationContext),
                fallback_mode: true
            });
        }

        return res.status(500).json({
            success: false,
            error: "Failed to process AI chat request",
            details: error.message
        });
    }
}

export async function getAIStatus(req, res) {
    try {
        const aiConfigured = isOpenAIConfigured();
        const mailConfigured = isMailConfigured();

        return res.status(200).json({
            success: true,
            ai_available: aiConfigured,
            analyze_fallback_available: true,
            chat_fallback_available: true,
            mail_available: mailConfigured,
            db_persistence_enabled: isPersistenceEnabled(),
            message: aiConfigured
                ? "AI service is configured"
                : "AI service is not configured (OPENAI_API_KEY missing). Set OPENAI_API_KEY in BACKEND/api/.env and restart Node API. Local fallback chat and analysis are enabled."
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            error: "Failed to check AI status",
            details: error.message
        });
    }
}

export async function downloadPDFReport(req, res) {
    const simulationId = parsePositiveInt(req.params.simulationId);

    if (!simulationId) {
        return res.status(400).json({
            success: false,
            error: "simulationId must be a positive integer"
        });
    }

    try {
        const { pdfBuffer } = await buildPdfReportPayload(simulationId);
        const filename = `horus-security-report-${simulationId}-${Date.now()}.pdf`;

        res.setHeader("Content-Type", "application/pdf");
        res.setHeader("Content-Disposition", `attachment; filename=\"${filename}\"`);
        res.setHeader("Content-Length", pdfBuffer.length);

        return res.send(pdfBuffer);
    } catch (error) {
        const statusCode = error.statusCode || (error.message.includes("Puppeteer") ? 503 : 500);

        return res.status(statusCode).json({
            success: false,
            error: error.statusCode ? error.message : "Failed to generate PDF report",
            details: error.details || (error.statusCode ? undefined : error.message)
        });
    }
}

export async function remediateSimulation(req, res) {
    const simulationId = parsePositiveInt(req.params.simulationId);

    if (!simulationId) {
        return res.status(400).json({
            success: false,
            error: "simulationId must be a positive integer"
        });
    }

    if (!isPersistenceEnabled()) {
        return res.status(503).json({
            success: false,
            error: "Database persistence is disabled"
        });
    }

    try {
        const simulation = await getSimulationById(simulationId);

        if (!simulation) {
            return res.status(404).json({
                success: false,
                error: `Simulation #${simulationId} not found`
            });
        }

        const scanPayload = extractScanPayloadFromSimulation(simulation) || {};
        const storedAnalysis = extractStoredAiAnalysis(simulation);
        const analysisResult = storedAnalysis || buildLocalHeuristicAnalysis(
            scanPayload?.raw || simulation.json_response || scanPayload
        );

        const plan = generateRemediationPlan(scanPayload, analysisResult);

        return res.status(200).json({
            success: true,
            simulation_id: simulationId,
            plan
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            error: "Failed to generate remediation plan",
            details: error.message
        });
    }
}

export async function emailPDFReport(req, res) {
    const simulationId = parsePositiveInt(req.params.simulationId);

    if (!simulationId) {
        return res.status(400).json({
            success: false,
            error: "simulationId must be a positive integer"
        });
    }

    const recipient = String(req.body?.email || req.body?.to || "").trim().toLowerCase();

    if (!recipient) {
        return res.status(400).json({
            success: false,
            error: "Recipient email is required in body.email"
        });
    }

    if (!isValidEmail(recipient)) {
        return res.status(400).json({
            success: false,
            error: "Recipient email format is invalid"
        });
    }

    if (!isMailConfigured()) {
        return res.status(503).json({
            success: false,
            error: "SMTP service is not configured. Set SMTP_HOST, SMTP_PORT, SMTP_FROM and credentials in BACKEND/api/.env."
        });
    }

    try {
        const { pdfBuffer, simulationMeta, normalizedReport } = await buildPdfReportPayload(simulationId);
        const filename = `horus-security-report-${simulationId}-${Date.now()}.pdf`;
        const subject = String(req.body?.subject || "").trim() || `HORUS | Reporte ejecutivo simulacion #${simulationId}`;
        const riskScore = normalizeRiskScoreTo100(normalizedReport?.risk_score);

        const textBody = [
            "HORUS - Reporte Ejecutivo de Seguridad",
            "",
            `Simulacion: #${simulationId}`,
            `Objetivo: ${simulationMeta.target}`,
            `Fecha de escaneo: ${formatDateTime(simulationMeta.scan_date)}`,
            `Riesgo global: ${riskScore}/100`,
            "",
            "Se adjunta el documento PDF con hallazgos, impacto y detalle de blindaje/remediacion aplicado por HORUS."
        ].join("\n");

        const htmlBody = [
            "<h2>HORUS - Reporte Ejecutivo de Seguridad</h2>",
            `<p><strong>Simulacion:</strong> #${simulationId}</p>`,
            `<p><strong>Objetivo:</strong> ${simulationMeta.target}</p>`,
            `<p><strong>Fecha de escaneo:</strong> ${formatDateTime(simulationMeta.scan_date)}</p>`,
            `<p><strong>Riesgo global:</strong> ${riskScore}/100</p>`,
            "<p>Se adjunta el documento PDF con hallazgos, impacto y detalle de blindaje/remediacion aplicado por HORUS.</p>"
        ].join("");

        const sendResult = await sendEmailMessage({
            to: recipient,
            subject,
            text: textBody,
            html: htmlBody,
            attachments: [
                {
                    filename,
                    content: pdfBuffer,
                    contentType: "application/pdf"
                }
            ]
        });

        return res.status(200).json({
            success: true,
            simulation_id: simulationId,
            recipient,
            message_id: sendResult?.messageId || null,
            accepted: Array.isArray(sendResult?.accepted) ? sendResult.accepted : [],
            rejected: Array.isArray(sendResult?.rejected) ? sendResult.rejected : []
        });
    } catch (error) {
        const statusCode = error.statusCode || (error.message.includes("Puppeteer") ? 503 : 500);

        return res.status(statusCode).json({
            success: false,
            error: error.statusCode ? error.message : (error.message || "Failed to email PDF report"),
            details: error.details || (error.statusCode ? undefined : error.message)
        });
    }
}
