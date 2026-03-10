// ============================================
// HORUS - SCANNER 
// ============================================
// EN: Frontend controller for network discovery and deep scan views.
// do.

const API_BASE = window.location.origin;
const API_SCAN = `${API_BASE}/api/simulations`;
const API_DISCOVER = `${API_BASE}/api/simulations/discover`;
const API_NETWORK = `${API_BASE}/api/simulations/network`;
const API_AI = `${API_BASE}/api/ai`;
const API_V2 = `${API_BASE}/api/v2`;
const API_V2_RISK = `${API_V2}/risk-score`;
const API_V2_FINDINGS = `${API_V2}/findings`;
const API_V2_CORRELATIONS = `${API_V2}/correlations`;

// ── DOM Elements ──
const modeTabs = document.getElementById('modeTabs');
const tabDiscover = document.getElementById('tabDiscover');
const tabScan = document.getElementById('tabScan');
const discoverCard = document.getElementById('discoverCard');
const scanCard = document.getElementById('scanCard');
const discoveryResults = document.getElementById('discoveryResults');
const scanResults = document.getElementById('scanResults');
const aiChatCard = document.getElementById('aiChatCard');
const aiChatWindow = document.getElementById('aiChatWindow');
const aiChatForm = document.getElementById('aiChatForm');
const aiChatInput = document.getElementById('aiChatInput');
const aiStatusBadge = document.getElementById('aiStatusBadge');
const aiLastSimulation = document.getElementById('aiLastSimulation');
const aiQuickActions = document.getElementById('aiQuickActions');

// Discover
const discoverForm = document.getElementById('discoverForm');
const subnetInput = document.getElementById('subnetInput');
const autoDetectBtn = document.getElementById('autoDetectBtn');
const autoDetectInfo = document.getElementById('autoDetectInfo');
const detectedNetwork = document.getElementById('detectedNetwork');
const detectedIP = document.getElementById('detectedIP');
const subnetValue = document.getElementById('subnetValue');
const hostsUp = document.getElementById('hostsUp');
const hostsTotal = document.getElementById('hostsTotal');
const discoverTime = document.getElementById('discoverTime');
const discoverCmdText = document.getElementById('discoverCmdText');
const devicesBody = document.getElementById('devicesBody');
const devicesEmpty = document.getElementById('devicesEmpty');
const devicesTable = document.getElementById('devicesTable');

// Scan
const scanForm = document.getElementById('scanForm');
const targetInput = document.getElementById('targetInput');
const hostValue = document.getElementById('hostValue');
const hostStatus = document.getElementById('hostStatus');
const portCount = document.getElementById('portCount');
const hydraCount = document.getElementById('hydraCount');
const scanTime = document.getElementById('scanTime');
const nmapCmdText = document.getElementById('nmapCmdText');
const networkGrid = document.getElementById('networkGrid');
const osCard = document.getElementById('osCard');
const osContent = document.getElementById('osContent');
const portsBody = document.getElementById('portsBody');
const portsEmpty = document.getElementById('portsEmpty');
const portsTable = document.getElementById('portsTable');
const traceCard = document.getElementById('traceCard');
const traceBody = document.getElementById('traceBody');
const vulnsCard = document.getElementById('vulnsCard');
const vulnsContent = document.getElementById('vulnsContent');
const hydraCard = document.getElementById('hydraCard');
const hydraCmdLog = document.getElementById('hydraCmdLog');
const hydraCmdText = document.getElementById('hydraCmdText');
const hydraBody = document.getElementById('hydraBody');
const hydraEmpty = document.getElementById('hydraEmpty');
const hydraTable = document.getElementById('hydraTable');
const scriptsCard = document.getElementById('scriptsCard');
const scriptsContent = document.getElementById('scriptsContent');

// Unified anti-ransomware monitor (vanilla, no React)
const unifiedRefreshBtn = document.getElementById('unifiedRefreshBtn');
const unifiedRiskScore = document.getElementById('unifiedRiskScore');
const unifiedRiskStatus = document.getElementById('unifiedRiskStatus');
const endpointMetrics = document.getElementById('endpointMetrics');
const unifiedFindingsTable = document.getElementById('unifiedFindingsTable');
const unifiedFindingsBody = document.getElementById('unifiedFindingsBody');
const unifiedFindingsEmpty = document.getElementById('unifiedFindingsEmpty');
const unifiedCorrelationsList = document.getElementById('unifiedCorrelationsList');
const remediationFindingId = document.getElementById('remediationFindingId');
const remediationPreviewBtn = document.getElementById('remediationPreviewBtn');
const remediationExecuteBtn = document.getElementById('remediationExecuteBtn');
const remediationOutput = document.getElementById('remediationOutput');

// Loading & Error
const loadingOverlay = document.getElementById("loadingOverlay");
const loadingText = document.getElementById("loadingText");
const loadingDetails = document.getElementById("loadingDetails");
const errorToast = document.getElementById("errorToast");
const errorMessage = document.getElementById("errorMessage");
const errorClose = document.getElementById("errorClose");

// ── Current Mode ──
let currentMode = 'discover';
let aiStatusLoaded = false;
let aiServiceReady = false;
let aiAnalysisReady = false;
let aiChatBootstrapped = false;
let currentSimulationId = null;
let aiChatHistory = [];
let unifiedLatestFindings = [];

// ── Tab Switching ──
function setMode(mode) {
    const nextMode = mode === 'scan' ? 'scan' : 'discover';
    currentMode = nextMode;

    document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
    const selectedTab = document.querySelector(`.tab[data-mode="${nextMode}"]`);
    if (selectedTab) {
        selectedTab.classList.add('active');
    }

    discoverCard.style.display = nextMode === 'discover' ? '' : 'none';
    scanCard.style.display = nextMode === 'scan' ? '' : 'none';

    if (nextMode !== 'discover') {
        discoveryResults.classList.remove('active');
    }

    if (nextMode !== 'scan') {
        scanResults.classList.remove('active');
    }
}

modeTabs.addEventListener('click', (e) => {
    const btn = e.target.closest('.tab');
    if (!btn) return;
    const mode = btn.dataset.mode;
    if (mode !== 'discover' && mode !== 'scan') return;
    if (mode === currentMode) return;
    setMode(mode);
});

// ── Validation / Validacion ──
// EN: Client-side format checks to avoid unnecessary API calls.
// ecesarias.
function isValidIP(ip) {
    return /^(25[0-5]|2[0-4]\d|[01]?\d\d?)(\.(25[0-5]|2[0-4]\d|[01]?\d\d?)){3}$/.test(ip.trim());
}
function isValidSubnet(subnet) {
    return /^(25[0-5]|2[0-4]\d|[01]?\d\d?)(\.(25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\/(2[0-9]|3[0-2]|[1][0-9]|[0-9])$/.test(subnet.trim());
}

// ── Loading / Carga ──
function showLoading(text, details) {
    loadingText.textContent = text || 'Escaneando...';
    loadingDetails.innerHTML = details || '';
    loadingOverlay.classList.add('active');
}
function hideLoading() { loadingOverlay.classList.remove('active'); }

function apiFetch(url, options = {}) {
    return fetch(url, options);
}

// ── Error / Errores ──
let errorTimeout = null;
function showError(msg) {
    errorMessage.textContent = msg;
    errorToast.classList.add('active');
    clearTimeout(errorTimeout);
    errorTimeout = setTimeout(() => hideError(), 6000);
}
function hideError() { errorToast.classList.remove('active'); clearTimeout(errorTimeout); }
errorClose.addEventListener('click', hideError);

// ── Utility / Utilidad: create badge / crear badge ──
function badge(text, type) {
    const s = document.createElement('span');
    s.className = `badge badge--${type}`;
    s.textContent = text;
    return s;
}

// ── Risk Bar / Barra de Riesgo ──
function createRiskBar(score) {
    const c = document.createElement('div');
    c.className = 'risk-bar';
    let level = score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low';
    const track = document.createElement('div');
    track.className = 'risk-bar__track';
    const fill = document.createElement('div');
    fill.className = `risk-bar__fill risk-bar__fill--${level}`;
    fill.style.width = '0%';
    track.appendChild(fill);
    const sc = document.createElement('span');
    sc.className = `risk-bar__score risk-bar__score--${level}`;
    sc.textContent = `${score}/10`;
    c.appendChild(track);
    c.appendChild(sc);
    requestAnimationFrame(() => requestAnimationFrame(() => { fill.style.width = `${(score / 10) * 100}%`; }));
    return c;
}

// ── Network info tile / Tarjeta de info de red ──
function createInfoTile(label, value) {
    const d = document.createElement('div');
    d.className = 'network-tile';
    d.innerHTML = `<span class="network-tile__label">${label}</span><span class="network-tile__value">${value || '--'}</span>`;
    return d;
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function appendAIMessage(role, htmlContent) {
    if (!aiChatWindow) return;

    const row = document.createElement('div');
    row.className = `ai-msg ai-msg--${role}`;

    const bubble = document.createElement('div');
    bubble.className = 'ai-msg__bubble';
    bubble.innerHTML = htmlContent;

    row.appendChild(bubble);
    aiChatWindow.appendChild(row);
    aiChatWindow.scrollTop = aiChatWindow.scrollHeight;
}

function updateAIStatusBadge(state, text) {
    if (!aiStatusBadge) return;

    aiStatusBadge.textContent = text;
    aiStatusBadge.classList.remove('badge--ai-online', 'badge--ai-offline', 'badge--ai-pending');
    aiStatusBadge.classList.add(`badge--ai-${state}`);
}

function updateAISimulationHint() {
    if (!aiLastSimulation) return;

    aiLastSimulation.textContent = currentSimulationId
        ? `Ultima simulacion: #${currentSimulationId}`
        : 'Ultima simulacion: --';
}

function parseSimulationId(text) {
    const safeText = String(text || '').replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '');
    const match = safeText.match(/(?:simulacion|simulation|id)?\s*#?\s*\b(\d{1,10})\b/i);
    if (!match) return null;

    const parsed = Number.parseInt(match[1], 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

function parseEmailFromMessage(text) {
    const match = String(text || '').match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    return match ? String(match[1]).trim().toLowerCase() : null;
}

function formatDateShort(value) {
    if (!value) return '--';

    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return String(value);
    }

    return date.toLocaleString();
}

async function resolveSimulationIdFromMessage(message, { allowHistoryFallback = true } = {}) {
    const normalized = String(message || '').toLowerCase();
    let simulationId = parseSimulationId(message);

    if (!simulationId && /ultima|ultimo|last|reciente|actual/.test(normalized)) {
        simulationId = currentSimulationId;
    }

    if (!simulationId && currentSimulationId && /(pdf|reporte|report|correo|email|mail|enviar|descargar|documento|ejecutivo)/.test(normalized)) {
        simulationId = currentSimulationId;
    }

    if (!simulationId && allowHistoryFallback) {
        try {
            const items = await fetchSimulationHistory(1);
            if (items.length > 0) {
                simulationId = Number.parseInt(String(items[0].id), 10);
            }
        } catch {
            simulationId = null;
        }
    }

    return Number.isFinite(simulationId) && simulationId > 0 ? simulationId : null;
}

function buildAIAnalysisSummary(simulationId, analysis, persistence) {
    const riskScoreRaw = Number.parseFloat(String(analysis?.overall_risk_score ?? analysis?.risk_score_global ?? 0));
    const riskScore = Number.isFinite(riskScoreRaw) ? riskScoreRaw : 0;
    const riskLevel = escapeHtml(analysis?.risk_level || (riskScore >= 7 ? 'HIGH' : riskScore >= 4 ? 'MEDIUM' : 'LOW'));
    const summary = escapeHtml(analysis?.executive_summary || 'Sin resumen disponible.');

    const vulnerabilities = Array.isArray(analysis?.vulnerabilities) ? analysis.vulnerabilities : [];
    const topVulns = vulnerabilities.slice(0, 3).map((vulnerability, index) => {
        const title = escapeHtml(vulnerability?.title || vulnerability?.script_id || `Vulnerabilidad ${index + 1}`);
        const severity = escapeHtml(String(vulnerability?.severity || 'medium').toUpperCase());
        return `- [${severity}] ${title}`;
    });

    const actions = Array.isArray(analysis?.immediate_actions) ? analysis.immediate_actions : [];
    const actionLines = actions.slice(0, 3).map((item, index) => `${index + 1}. ${escapeHtml(item)}`);

    const persistLine = persistence?.stored
        ? 'Analisis guardado en base de datos.'
        : persistence?.enabled
            ? `Analisis no guardado: ${escapeHtml(persistence?.error || persistence?.reason || 'sin detalle')}`
            : `Persistencia deshabilitada: ${escapeHtml(persistence?.reason || 'sin detalle')}`;

    return [
        `Analisis completado para la simulacion #${simulationId}.`,
        `Riesgo global: ${riskScore}/10 (${riskLevel}).`,
        `Resumen ejecutivo: ${summary}`,
        topVulns.length > 0 ? `Hallazgos principales:<br>${topVulns.join('<br>')}` : 'Hallazgos principales: no se reportaron vulnerabilidades relevantes.',
        actionLines.length > 0 ? `Acciones inmediatas:<br>${actionLines.join('<br>')}` : 'Acciones inmediatas: no reportadas.',
        persistLine,
        'Tip: escribe "descargar reporte ejecutivo ultima" o "enviar reporte ejecutivo ultima a correo@dominio.com".'
    ].join('<br><br>');
}

async function checkAIStatus(silent = false) {
    updateAIStatusBadge('pending', 'IA: verificando...');

    try {
        const response = await apiFetch(`${API_AI}/status`);
        const payload = await response.json().catch(() => ({}));

        if (!response.ok) {
            throw new Error(payload.error || `Error del servidor (${response.status})`);
        }

        aiStatusLoaded = true;
        aiServiceReady = Boolean(payload.ai_available);
        aiAnalysisReady = aiServiceReady || Boolean(payload.analyze_fallback_available);

        if (aiServiceReady) {
            updateAIStatusBadge('online', 'IA: online');
        } else if (aiAnalysisReady) {
            updateAIStatusBadge('offline', 'IA: modo local');
        } else {
            updateAIStatusBadge('offline', 'IA: offline');
        }

        if (!silent) {
            const aiLine = aiServiceReady
                ? 'OpenAI activo: analisis y chat generativo disponibles.'
                : aiAnalysisReady
                    ? 'OpenAI no configurado: define OPENAI_API_KEY en BACKEND/api/.env y reinicia Node API. Mientras tanto se usa modo local.'
                    : 'IA no disponible.';
            const analyzeLine = payload.analyze_fallback_available
                ? 'Analisis fallback local: activo.'
                : 'Analisis fallback local: no disponible.';
            const fallbackLine = payload.chat_fallback_available
                ? 'Chat fallback local: activo.'
                : 'Chat fallback local: no disponible.';
            const dbLine = payload.db_persistence_enabled
                ? 'Persistencia DB: activa.'
                : 'Persistencia DB: desactivada.';
            const mailLine = payload.mail_available
                ? 'Envio por correo: configurado.'
                : 'Envio por correo: no configurado (SMTP_HOST/SMTP_FROM).';
            appendAIMessage('assistant', `${aiLine}<br>${analyzeLine}<br>${fallbackLine}<br>${dbLine}<br>${mailLine}`);
        }

        return payload;
    } catch (error) {
        aiStatusLoaded = true;
        aiServiceReady = false;
        aiAnalysisReady = false;
        updateAIStatusBadge('offline', 'IA: offline');

        if (!silent) {
            appendAIMessage('assistant', `No pude validar el estado de IA: ${escapeHtml(error.message)}`);
        }

        return null;
    }
}

async function fetchSimulationHistory(limit = 5) {
    const response = await apiFetch(`${API_SCAN}/history`);
    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
        throw new Error(payload.error || payload.detail || `Error del servidor (${response.status})`);
    }

    const items = Array.isArray(payload.items) ? payload.items : [];
    return items.slice(0, limit);
}

async function analyzeStoredSimulationById(simulationId) {
    if (!Number.isFinite(simulationId) || simulationId <= 0) {
        appendAIMessage('assistant', 'Debes indicar un ID de simulacion valido.');
        return;
    }

    if (!aiStatusLoaded || !aiAnalysisReady) {
        await checkAIStatus(true);
    }

    if (!aiAnalysisReady) {
        appendAIMessage('assistant', 'El analisis no esta disponible en este momento. Revisa estado IA y base de datos.');
        return;
    }

    if (!aiServiceReady) {
        appendAIMessage('system', `Analizando simulacion #${simulationId} en modo local (sin OpenAI)...`);
    } else {
        appendAIMessage('system', `Analizando simulacion #${simulationId}...`);
    }

    try {
        const response = await apiFetch(`${API_AI}/analyze/simulation/${simulationId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });

        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new Error(payload.error || payload.details || `Error del servidor (${response.status})`);
        }

        currentSimulationId = simulationId;
        updateAISimulationHint();
        appendAIMessage('assistant', buildAIAnalysisSummary(simulationId, payload.analysis || {}, payload.persistence));

        if (payload.fallback_mode) {
            appendAIMessage('system', 'Analisis generado con motor local heuristico (sin OpenAI).');
        }
    } catch (error) {
        appendAIMessage('assistant', `No se pudo analizar la simulacion #${simulationId}: ${escapeHtml(error.message)}`);
    }
}

async function downloadPDFReportById(simulationId) {
    if (!Number.isFinite(simulationId) || simulationId <= 0) {
        appendAIMessage('assistant', 'Debes indicar un ID valido para descargar PDF.');
        return;
    }

    appendAIMessage('system', `Generando PDF para simulacion #${simulationId}...`);

    try {
        const response = await apiFetch(`${API_AI}/report/${simulationId}/pdf`);
        if (!response.ok) {
            const payload = await response.json().catch(() => ({}));
            throw new Error(payload.error || payload.details || `Error del servidor (${response.status})`);
        }

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `horus-security-report-${simulationId}-${Date.now()}.pdf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);

        appendAIMessage('assistant', `PDF descargado para simulacion #${simulationId}.`);
    } catch (error) {
        const details = String(error.message || '');
        if (/No stored AI analysis/i.test(details)) {
            appendAIMessage('assistant', `No hay analisis IA guardado para #${simulationId}. Primero ejecuta: \"analiza simulacion ${simulationId}\".`);
            return;
        }

        appendAIMessage('assistant', `No se pudo descargar el PDF: ${escapeHtml(details)}`);
    }
}

async function sendPDFReportByEmail(simulationId, recipientEmail) {
    if (!Number.isFinite(simulationId) || simulationId <= 0) {
        appendAIMessage('assistant', 'Debes indicar un ID valido para enviar el reporte por correo.');
        return;
    }

    if (!recipientEmail) {
        appendAIMessage('assistant', 'Debes indicar un correo destino valido.');
        return;
    }

    appendAIMessage('system', `Preparando reporte #${simulationId} para ${escapeHtml(recipientEmail)}...`);

    // Try server-side SMTP first
    try {
        const response = await apiFetch(`${API_AI}/report/${simulationId}/email`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: recipientEmail })
        });

        const payload = await response.json().catch(() => ({}));

        if (response.ok) {
            const accepted = Array.isArray(payload.accepted) && payload.accepted.length > 0
                ? ` Destinatarios aceptados: ${escapeHtml(payload.accepted.join(', '))}.`
                : '';
            appendAIMessage('assistant', `Reporte ejecutivo enviado a ${escapeHtml(recipientEmail)}.${accepted}`);
            return;
        }

        const errorText = `${payload.error || ''} ${payload.details || ''}`;
        const isSmtpError = /SMTP|not configured|503/i.test(errorText);
        if (!isSmtpError) {
            throw new Error(payload.error || payload.details || `Error del servidor (${response.status})`);
        }
    } catch (serverError) {
        const msg = String(serverError.message || '');
        if (!/SMTP|not configured|fetch|network/i.test(msg)) {
            appendAIMessage('assistant', `No se pudo enviar el correo: ${escapeHtml(msg)}`);
            return;
        }
    }

    // Client-side fallback: download PDF + open email client
    appendAIMessage('system', 'SMTP no configurado. Preparando envio desde tu cliente de correo...');

    try {
        const response = await apiFetch(`${API_AI}/report/${simulationId}/pdf`);
        if (!response.ok) {
            const payload = await response.json().catch(() => ({}));
            throw new Error(payload.error || payload.details || `Error generando PDF (${response.status})`);
        }

        const blob = await response.blob();
        const filename = `horus-security-report-${simulationId}.pdf`;

        // Auto-download the PDF
        const downloadUrl = window.URL.createObjectURL(blob);
        const downloadLink = document.createElement('a');
        downloadLink.href = downloadUrl;
        downloadLink.download = filename;
        document.body.appendChild(downloadLink);
        downloadLink.click();
        document.body.removeChild(downloadLink);
        window.URL.revokeObjectURL(downloadUrl);

        // Open email client with pre-filled fields
        const subject = encodeURIComponent(`HORUS | Reporte de Seguridad - Simulacion #${simulationId}`);
        const body = encodeURIComponent(
            `Adjunto encontrara el reporte de seguridad generado por HORUS para la simulacion #${simulationId}.\n\n` +
            `Por favor revise los hallazgos y recomendaciones incluidas en el documento PDF adjunto.\n\n` +
            `--- Enviado desde HORUS Security Scanner ---`
        );
        const mailtoUrl = `mailto:${encodeURIComponent(recipientEmail)}?subject=${subject}&body=${body}`;
        window.open(mailtoUrl, '_blank');

        appendAIMessage('assistant',
            `PDF descargado como "${filename}".\n\n` +
            `Se abrio tu cliente de correo con el destinatario ${escapeHtml(recipientEmail)} pre-configurado.\n\n` +
            `Adjunta el archivo PDF descargado al correo y envialo.`
        );
    } catch (error) {
        appendAIMessage('assistant', `No se pudo preparar el reporte: ${escapeHtml(error.message)}`);
    }
}

function addAIChatHistory(role, content) {
    const safeRole = role === 'assistant' ? 'assistant' : 'user';
    const safeContent = String(content || '').trim();

    if (!safeContent) {
        return;
    }

    aiChatHistory.push({
        role: safeRole,
        content: safeContent.slice(0, 2000)
    });

    if (aiChatHistory.length > 12) {
        aiChatHistory = aiChatHistory.slice(-12);
    }
}

function formatAssistantTextToHtml(text) {
    return escapeHtml(String(text || '')).replace(/\n/g, '<br>');
}

async function askFreeChatToAIAgent(message) {
    appendAIMessage('system', 'Consultando agente IA...');

    try {
        const response = await apiFetch(`${API_AI}/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message,
                simulation_id: currentSimulationId,
                conversation: aiChatHistory
            })
        });

        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new Error(payload.error || payload.details || `Error del servidor (${response.status})`);
        }

        const reply = String(payload.reply || '').trim();
        if (!reply) {
            throw new Error('La IA no devolvio contenido');
        }

        addAIChatHistory('user', message);
        addAIChatHistory('assistant', reply);

        const responseSimulationId = Number.parseInt(String(payload.simulation_id || ''), 10);
        if (Number.isFinite(responseSimulationId) && responseSimulationId > 0) {
            currentSimulationId = responseSimulationId;
            updateAISimulationHint();
        }

        appendAIMessage('assistant', formatAssistantTextToHtml(reply));
    } catch (error) {
        const details = String(error.message || '');

        if (/AI chat service is not available/i.test(details)) {
            appendAIMessage(
                'assistant',
                'El chat generativo no esta disponible ahora. Puedes usar: "estado ia", "historial", "descargar reporte ejecutivo ultima" o "enviar reporte ejecutivo ultima a correo@dominio.com".'
            );
            return;
        }

        appendAIMessage('assistant', `No pude obtener respuesta del agente IA: ${escapeHtml(details)}`);
    }
}

async function handleAIQuickAction(action) {
    switch (action) {
        case 'status':
            await handleAIUserMessage('estado ia');
            break;
        case 'history':
            await handleAIUserMessage('historial');
            break;
        case 'analyze-last':
            await handleAIUserMessage('analiza ultima');
            break;
        case 'download-last':
            await handleAIUserMessage('descargar reporte ejecutivo ultima');
            break;
        case 'email-last': {
            const email = await openEmailModal();
            if (!email) {
                appendAIMessage('assistant', 'Envio por correo cancelado.');
                return;
            }
            await handleAIUserMessage(`enviar reporte ejecutivo ultima a ${email.trim()}`);
            break;
        }
        case 'help':
            await handleAIUserMessage('ayuda');
            break;
        default:
            break;
    }
}

function openEmailModal() {
    return new Promise((resolve) => {
        const overlay = document.getElementById('emailModalOverlay');
        const input = document.getElementById('emailModalInput');
        const sendBtn = document.getElementById('emailModalSend');
        const cancelBtn = document.getElementById('emailModalCancel');
        const closeBtn = document.getElementById('emailModalClose');
        const errorEl = document.getElementById('emailModalError');

        if (!overlay || !input) {
            const fallback = prompt('Correo destino para enviar el reporte ejecutivo:');
            resolve(fallback || null);
            return;
        }

        input.value = '';
        errorEl.textContent = '';
        overlay.classList.add('active');
        setTimeout(() => input.focus(), 150);

        function cleanup() {
            overlay.classList.remove('active');
            sendBtn.removeEventListener('click', handleSend);
            cancelBtn.removeEventListener('click', handleCancel);
            closeBtn.removeEventListener('click', handleCancel);
            overlay.removeEventListener('click', handleOverlayClick);
            document.removeEventListener('keydown', handleKeydown);
        }

        function validateEmail(email) {
            return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
        }

        function handleSend() {
            const email = input.value.trim();
            if (!email) {
                errorEl.textContent = 'Ingrese un correo electronico.';
                input.focus();
                return;
            }
            if (!validateEmail(email)) {
                errorEl.textContent = 'Formato de correo invalido.';
                input.focus();
                return;
            }
            cleanup();
            resolve(email);
        }

        function handleCancel() {
            cleanup();
            resolve(null);
        }

        function handleOverlayClick(e) {
            if (e.target === overlay) handleCancel();
        }

        function handleKeydown(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                handleSend();
            } else if (e.key === 'Escape') {
                handleCancel();
            }
        }

        sendBtn.addEventListener('click', handleSend);
        cancelBtn.addEventListener('click', handleCancel);
        closeBtn.addEventListener('click', handleCancel);
        overlay.addEventListener('click', handleOverlayClick);
        document.addEventListener('keydown', handleKeydown);
    });
}

async function handleAIUserMessage(rawMessage) {
    const message = String(rawMessage || '').trim();
    if (!message) return;

    appendAIMessage('user', escapeHtml(message));

    const normalized = message.toLowerCase();

    if (/ayuda|help|comandos/.test(normalized)) {
        appendAIMessage(
            'assistant',
            'Comandos disponibles:<br>' +
            '- estado ia<br>' +
            '- historial<br>' +
            '- analiza simulacion 12<br>' +
            '- analiza ultima<br>' +
            '- descargar reporte ejecutivo 12<br>' +
            '- descargar reporte ejecutivo ultima<br>' +
            '- enviar reporte ejecutivo 12 a correo@dominio.com<br>' +
            '- enviar reporte ejecutivo ultima a correo@dominio.com<br>' +
            '- faq (preguntas frecuentes de la aplicacion)<br>- pregunta libre (ej: "que recomiendas endurecer primero?")'
        );
        return;
    }

    if (/estado|status/.test(normalized)) {
        await checkAIStatus(false);
        return;
    }

    if (/historial|history|ultimas|ultimos/.test(normalized)) {
        try {
            const items = await fetchSimulationHistory(5);
            if (items.length === 0) {
                appendAIMessage('assistant', 'No hay simulaciones guardadas todavia.');
                return;
            }

            if (!currentSimulationId) {
                const latestId = Number.parseInt(String(items[0].id), 10);
                currentSimulationId = Number.isFinite(latestId) && latestId > 0 ? latestId : null;
                updateAISimulationHint();
            }

            const rows = items.map((item) => {
                const target = escapeHtml(item.target_ip || item.target_subnet || '--');
                const status = escapeHtml(item.status || '--');
                const type = escapeHtml(item.scan_type || '--');
                const date = escapeHtml(formatDateShort(item.created_at));
                return `#${item.id} | ${type} | ${target} | ${status} | ${date}`;
            });

            appendAIMessage('assistant', `Ultimas simulaciones:<br>${rows.join('<br>')}`);
        } catch (error) {
            appendAIMessage('assistant', `No pude consultar historial: ${escapeHtml(error.message)}`);
        }
        return;
    }

    if (/analiza|analizar|analysis|evalua|evaluar/.test(normalized)) {
        const simulationId = await resolveSimulationIdFromMessage(message, { allowHistoryFallback: true });

        if (!simulationId) {
            appendAIMessage('assistant', 'No encontre simulaciones para analizar. Ejecuta un escaneo y luego intenta de nuevo.');
            return;
        }

        await analyzeStoredSimulationById(simulationId);
        return;
    }

    if (/(correo|email|mail|enviar)/.test(normalized) && /(pdf|reporte|report|documento|ejecutivo)/.test(normalized)) {
        const recipientEmail = parseEmailFromMessage(message);
        if (!recipientEmail) {
            appendAIMessage('assistant', 'Indica un correo destino. Ejemplo: "enviar reporte ejecutivo ultima a analista@empresa.com".');
            return;
        }

        const simulationId = await resolveSimulationIdFromMessage(message, { allowHistoryFallback: true });
        if (!simulationId) {
            appendAIMessage('assistant', 'No encontre simulacion para enviar. Usa "historial" y vuelve a intentar con un ID.');
            return;
        }

        await sendPDFReportByEmail(simulationId, recipientEmail);
        return;
    }

    if (/pdf|reporte|report|descarga|descargar|documento|ejecutivo/.test(normalized)) {
        const simulationId = await resolveSimulationIdFromMessage(message, { allowHistoryFallback: true });

        if (!simulationId) {
            appendAIMessage('assistant', 'No encontre simulacion para descargar. Usa "historial" o indica un ID, por ejemplo: "descargar reporte ejecutivo 12".');
            return;
        }

        await downloadPDFReportById(simulationId);
        return;
    }

    if (/hola|buenas|hello|hi/.test(normalized)) {
        await askFreeChatToAIAgent(message);
        return;
    }

    await askFreeChatToAIAgent(message);
}

async function bootstrapAIChat() {
    if (aiChatBootstrapped) return;
    aiChatBootstrapped = true;

    updateAISimulationHint();

    appendAIMessage(
        'assistant',
        'Soy HORUS IA. Puedo revisar historial, analizar simulaciones guardadas, generar reportes ejecutivos PDF, enviarlos por correo y conversar sobre seguridad.'
    );

    appendAIMessage(
        'system',
        'Prueba con: "estado ia", "faq", "historial", "analiza ultima", "descargar reporte ejecutivo ultima" o "enviar reporte ejecutivo ultima a correo@dominio.com".'
    );

    if (!hasActiveSession()) {
        updateAIStatusBadge('pending', 'IA: inicia sesion');
        return;
    }

    await checkAIStatus(true);

    try {
        const items = await fetchSimulationHistory(1);
        if (items.length > 0) {
            const latestId = Number.parseInt(String(items[0].id), 10);
            currentSimulationId = Number.isFinite(latestId) && latestId > 0 ? latestId : null;
            updateAISimulationHint();
        }
    } catch {
        // No-op: historial puede no estar disponible.
    }
}


// ═══════════════════════════════════════
// AUTO-DETECT NETWORK
// ═══════════════════════════════════════
autoDetectBtn.addEventListener('click', async () => {
    try {
        const res = await apiFetch(API_NETWORK);
        if (!res.ok) throw new Error('No se pudo detectar la red');
        const data = await res.json();
        if (data.networks && data.networks.length > 0) {
            const net = data.networks[0];
            // Use scan_subnet (capped at /24) for scanning, show full subnet for info
            const scanSubnet = net.scan_subnet || net.subnet;
            subnetInput.value = scanSubnet;
            detectedNetwork.textContent = scanSubnet !== net.subnet
                ? `${scanSubnet} (detectada: ${net.subnet})`
                : net.subnet;
            detectedIP.textContent = `${net.ip} (${net.interface})`;
            autoDetectInfo.style.display = 'flex';
        } else {
            showError('No se detectaron interfaces de red activas');
        }
    } catch (err) {
        showError(err.message);
    }
});

// ═══════════════════════════════════════
// NETWORK DISCOVERY
// ═══════════════════════════════════════
function renderDiscoveryResults(data) {
    // EN: Update summary metrics and command log.
    // do.
    subnetValue.textContent = data.subnet || '--';
    hostsUp.textContent = data.hosts_up || 0;
    hostsTotal.textContent = data.hosts_total || 0;
    discoverTime.textContent = data.scan_time ? `${data.scan_time}s` : '--';
    discoverCmdText.textContent = data.nmap_command || '--';

    if (Array.isArray(data.warnings) && data.warnings.length > 0) {
        showError(data.warnings[0]);
    }

    devicesBody.innerHTML = '';
    if (!data.devices || data.devices.length === 0) {
        devicesTable.querySelector('thead').style.display = 'none';
        devicesEmpty.style.display = 'block';
        discoveryResults.classList.add('active');
        return;
    }
    devicesTable.querySelector('thead').style.display = '';
    devicesEmpty.style.display = 'none';

    data.devices.forEach((d, i) => {
        const row = document.createElement('tr');
        row.style.animation = `fadeSlideUp 0.4s ease ${i * 0.05}s both`;
        row.innerHTML = `
            <td>${d.ip}</td>
            <td>${d.hostname || '--'}</td>
            <td>${d.mac || '--'}</td>
            <td>${d.vendor || '--'}</td>
            <td></td>
        `;
        const scanLink = document.createElement('button');
        scanLink.className = 'btn-scan-device';
        scanLink.textContent = 'ESCANEAR';
        scanLink.addEventListener('click', () => {
            tabScan.click();
            targetInput.value = d.ip;
            scanForm.dispatchEvent(new Event('submit'));
        });
        row.lastElementChild.appendChild(scanLink);
        devicesBody.appendChild(row);
    });
    discoveryResults.classList.add('active');
}

async function launchDiscovery(subnet) {
    // EN: Network-discovery request lifecycle.
    // to de red.
    showLoading('Descubriendo dispositivos...', `Escaneando ${subnet} con Nmap ping scan`);
    hideError();
    try {
        const res = await apiFetch(API_DISCOVER, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ subnet })
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || `Error del servidor (${res.status})`);
        }
        renderDiscoveryResults(await res.json());
    } catch (err) {
        showError(err.message);
    } finally {
        hideLoading();
    }
}

discoverForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const subnet = subnetInput.value.trim();
    if (!subnet) { subnetInput.classList.add('input--error'); showError('Ingresa una subred CIDR'); setTimeout(() => subnetInput.classList.remove('input--error'), 600); return; }
    if (!isValidSubnet(subnet)) { subnetInput.classList.add('input--error'); showError('Formato invalido. Usa CIDR, ej: 192.168.1.0/24'); setTimeout(() => subnetInput.classList.remove('input--error'), 600); return; }
    launchDiscovery(subnet);
});
subnetInput.addEventListener('input', () => subnetInput.classList.remove('input--error'));

// ═══════════════════════════════════════
// DEEP SCAN
// ═══════════════════════════════════════

function renderNetworkInfo(data) {
    const info = data.network_info || {};
    networkGrid.innerHTML = '';

    const tiles = [
        ['IP del Host', info.host_ip],
        ['Hostname', info.hostname],
        ['MAC', info.mac_address],
        ['Fabricante', info.mac_vendor],
        ['Tipo de Dispositivo', info.device_type],
        ['Puertos Abiertos', info.open_ports_count],
        ['Saltos Traceroute', info.traceroute_hops],
        ['Vulnerabilidades', info.vulnerabilities_count],
        ['Nmap Version', data.nmap_version],
        ['Servicios Detectados', (info.services_detected || []).join(', ') || 'Ninguno']
    ];

    tiles.forEach(([label, val]) => networkGrid.appendChild(createInfoTile(label, val)));
}

function renderOSDetection(data) {
    const os = data.os_detection;
    const allOS = data.network_info?.all_os_matches || [];

    if (!os && allOS.length === 0) { osCard.style.display = 'none'; return; }

    osCard.style.display = '';
    osContent.innerHTML = '';

    if (os) {
        const main = document.createElement('div');
        main.className = 'os-main';
        main.innerHTML = `
            <div class="os-main__name">${os.name}</div>
            <div class="os-main__details">
                <span>Precision: ${os.accuracy}%</span>
                ${os.os_family ? `<span>Familia: ${os.os_family}</span>` : ''}
                ${os.vendor ? `<span>Fabricante: ${os.vendor}</span>` : ''}
                ${os.type ? `<span>Tipo: ${os.type}</span>` : ''}
                ${os.cpe ? `<span>CPE: ${os.cpe}</span>` : ''}
            </div>
        `;
        osContent.appendChild(main);
    }

    if (allOS.length > 1) {
        const othersTitle = document.createElement('p');
        othersTitle.className = 'os-others-title';
        othersTitle.textContent = 'Otras coincidencias:';
        osContent.appendChild(othersTitle);

        allOS.slice(1, 5).forEach(m => {
            const row = document.createElement('div');
            row.className = 'os-other-match';
            row.innerHTML = `<span>${m.name}</span><span class="os-other-match__accuracy">${m.accuracy}%</span>`;
            osContent.appendChild(row);
        });
    }
}

function renderPorts(ports) {
    portsBody.innerHTML = '';
    if (!ports || ports.length === 0) {
        portsTable.querySelector('thead').style.display = 'none';
        portsEmpty.style.display = 'block';
        return;
    }
    portsTable.querySelector('thead').style.display = '';
    portsEmpty.style.display = 'none';

    ports.forEach((p, i) => {
        const row = document.createElement('tr');
        row.style.animation = `fadeSlideUp 0.4s ease ${i * 0.05}s both`;

        const stateCell = document.createElement('td');
        stateCell.appendChild(badge(p.state || 'unknown', p.state === 'open' ? 'open' : p.state === 'closed' ? 'closed' : 'filtered'));

        row.innerHTML = `<td>${p.port}/${p.protocol || 'tcp'}</td>`;
        row.appendChild(stateCell);

        const svcCell = document.createElement('td');
        svcCell.textContent = p.service || '--';
        row.appendChild(svcCell);

        const prodCell = document.createElement('td');
        prodCell.textContent = p.product || '--';
        row.appendChild(prodCell);

        const verCell = document.createElement('td');
        verCell.textContent = p.version || '--';
        row.appendChild(verCell);

        const infoCell = document.createElement('td');
        infoCell.textContent = p.extra_info || (p.cpe ? p.cpe : '--');
        row.appendChild(infoCell);

        portsBody.appendChild(row);
    });
}

function renderTraceroute(trace) {
    if (!trace || trace.length === 0) { traceCard.style.display = 'none'; return; }
    traceCard.style.display = '';
    traceBody.innerHTML = '';
    trace.forEach((h, i) => {
        const row = document.createElement('tr');
        row.style.animation = `fadeSlideUp 0.3s ease ${i * 0.04}s both`;
        row.innerHTML = `
            <td>${h.ttl}</td>
            <td>${h.ip || '--'}</td>
            <td>${h.hostname || '--'}</td>
            <td>${h.rtt ? h.rtt + ' ms' : '--'}</td>
        `;
        traceBody.appendChild(row);
    });
}

function renderVulnerabilities(vulns) {
    if (!vulns || vulns.length === 0) { vulnsCard.style.display = 'none'; return; }
    vulnsCard.style.display = '';
    vulnsContent.innerHTML = '';
    vulns.forEach(v => {
        const d = document.createElement('div');
        d.className = `vuln-item vuln-item--${v.severity}`;
        d.innerHTML = `
            <div class="vuln-item__header">
                <span class="vuln-item__id">${v.script_id}</span>
                <span class="vuln-item__severity">${v.severity.toUpperCase()}</span>
            </div>
            <pre class="vuln-item__output">${v.output}</pre>
        `;
        vulnsContent.appendChild(d);
    });
}

function renderHydra(credentialTests, hydraCommands) {
    // EN: Render Hydra execution details and defensive-signal states.
    // sivas.
    hydraBody.innerHTML = '';

    // Show Hydra commands
    if (hydraCommands && hydraCommands.length > 0) {
        hydraCmdLog.style.display = '';
        hydraCmdText.textContent = hydraCommands.map(c => `[Puerto ${c.port}/${c.service}] ${c.command}`).join('\n');
    } else {
        hydraCmdLog.style.display = 'none';
    }

    if (!credentialTests || credentialTests.length === 0) {
        hydraTable.querySelector('thead').style.display = 'none';
        hydraEmpty.style.display = 'block';
        return;
    }
    hydraTable.querySelector('thead').style.display = '';
    hydraEmpty.style.display = 'none';

    const getHydraBadge = (status) => {
        switch (status) {
            case 'credentials_found':
                return ['CREDENCIALES ENCONTRADAS', 'creds-found'];
            case 'lockout_detected':
                return ['LOCKOUT DETECTADO', 'alert'];
            case 'rate_limited':
                return ['RATE LIMIT', 'warning'];
            case 'max_duration_reached':
                return ['MAX DURACION', 'warning'];
            case 'skipped_cooldown':
                return ['COOLDOWN ACTIVO', 'paused'];
            case 'skipped_auto_stop':
                return ['AUTO-STOP', 'paused'];
            case 'hydra_error':
                return ['ERROR HYDRA', 'error'];
            default:
                return ['SEGURO', 'no-creds'];
        }
    };

    credentialTests.forEach((ct, i) => {
        const row = document.createElement('tr');
        row.style.animation = `fadeSlideUp 0.4s ease ${i * 0.08}s both`;

        const portCell = document.createElement('td');
        portCell.textContent = ct.port;

        const svcCell = document.createElement('td');
        svcCell.textContent = ct.service || '--';

        const statusCell = document.createElement('td');
        const [label, type] = getHydraBadge(ct.status);
        statusCell.appendChild(badge(label, type));

        const riskCell = document.createElement('td');
        riskCell.appendChild(createRiskBar(ct.risk_score));

        const detailCell = document.createElement('td');
        if (ct.details) {
            detailCell.innerHTML = `<span class="cred-detail">${ct.details.user}:${ct.details.password}</span>`;
        } else if (ct.output_summary) {
            detailCell.textContent = ct.output_summary.substring(0, 80);
        } else {
            detailCell.textContent = 'Sin hallazgos';
        }

        row.appendChild(portCell);
        row.appendChild(svcCell);
        row.appendChild(statusCell);
        row.appendChild(riskCell);
        row.appendChild(detailCell);
        hydraBody.appendChild(row);
    });
}

function renderHostScripts(scripts) {
    if (!scripts || scripts.length === 0) { scriptsCard.style.display = 'none'; return; }
    scriptsCard.style.display = '';
    scriptsContent.innerHTML = '';
    scripts.forEach(s => {
        const d = document.createElement('div');
        d.className = 'script-item';
        d.innerHTML = `
            <div class="script-item__id">${s.id}</div>
            <pre class="script-item__output">${s.output}</pre>
        `;
        scriptsContent.appendChild(d);
    });
}

function renderScanResults(data) {
    // EN: Render full deep-scan response in all cards/tables.
    // tarjetas/tablas.
    // Info bar
    hostValue.textContent = data.hostname ? `${data.host} (${data.hostname})` : (data.host || '--');
    hostStatus.textContent = data.status === 'up' ? 'ACTIVO' : (data.status === 'down' ? 'INACTIVO' : data.status);
    hostStatus.className = `info-bar__value ${data.status === 'up' ? 'info-bar__value--up' : 'info-bar__value--down'}`;
    portCount.textContent = (data.ports || []).filter(p => p.state === 'open').length;
    hydraCount.textContent = (data.credential_tests || []).length;
    scanTime.textContent = data.scan_time ? `${data.scan_time}s` : '--';

    if (data.simulation_id) {
        const parsedSimulationId = Number.parseInt(String(data.simulation_id), 10);
        if (Number.isFinite(parsedSimulationId) && parsedSimulationId > 0) {
            currentSimulationId = parsedSimulationId;
            updateAISimulationHint();

            if (aiChatBootstrapped) {
                appendAIMessage('system', `Se detecto nueva simulacion #${parsedSimulationId}. Escribe "analiza ultima" para evaluarla con IA.`);
            }
        }
    }

    // Nmap command
    nmapCmdText.textContent = data.nmap_command || '--';

    // Render all sections
    renderNetworkInfo(data);
    renderOSDetection(data);
    renderPorts(data.ports);
    renderTraceroute(data.traceroute);
    renderVulnerabilities(data.vulnerabilities);
    renderHydra(data.credential_tests, data.hydra_commands);
    renderHostScripts(data.host_scripts);

    scanResults.classList.add('active');
}

function getUnifiedRiskLevel(score) {
    if (score >= 75) return 'CRITICAL';
    if (score >= 50) return 'HIGH';
    if (score >= 25) return 'MEDIUM';
    return 'LOW';
}

function renderUnifiedRisk(risk) {
    if (!unifiedRiskScore || !unifiedRiskStatus) return;

    const value = Number.parseInt(String(risk?.score ?? 0), 10) || 0;
    const level = getUnifiedRiskLevel(value);

    unifiedRiskScore.textContent = `${value}/100`;
    unifiedRiskStatus.textContent = level;
    unifiedRiskStatus.dataset.level = level;
}

function renderEndpointMetrics(metrics) {
    if (!endpointMetrics) return;

    const entries = [
        ['Files Modified/s', metrics?.files_modified_per_second ?? 0],
        ['Files Renamed/s', metrics?.files_renamed_per_second ?? 0],
        ['Entropy Avg', metrics?.entropy_avg_modified_files ?? 0],
        ['Entropy Delta', metrics?.entropy_delta ?? 0],
        ['Honeypot Touched', String(Boolean(metrics?.honeypot_touched))],
        ['VSS Delete Attempt', String(Boolean(metrics?.vss_delete_attempt))],
    ];

    endpointMetrics.innerHTML = entries
        .map(([label, value]) => `
            <div class="unified-metric">
                <span class="unified-metric__label">${escapeHtml(label)}</span>
                <span class="unified-metric__value">${escapeHtml(String(value))}</span>
            </div>
        `)
        .join('');
}

function renderUnifiedFindings(items) {
    if (!unifiedFindingsBody || !unifiedFindingsEmpty || !unifiedFindingsTable) return;

    unifiedFindingsBody.innerHTML = '';
    const list = Array.isArray(items) ? items.slice(0, 10) : [];

    if (list.length === 0) {
        unifiedFindingsTable.querySelector('thead').style.display = 'none';
        unifiedFindingsEmpty.style.display = 'block';
        return;
    }

    unifiedFindingsTable.querySelector('thead').style.display = '';
    unifiedFindingsEmpty.style.display = 'none';

    list.forEach((item, index) => {
        const row = document.createElement('tr');
        row.style.animation = `fadeSlideUp 0.3s ease ${index * 0.03}s both`;
        row.innerHTML = `
            <td>${escapeHtml(String(item.id || '').slice(0, 8))}</td>
            <td>${escapeHtml(item.source || '--')}</td>
            <td>${escapeHtml(item.finding_type || '--')}</td>
            <td>${escapeHtml(item.severity || '--')}</td>
            <td>${escapeHtml(String(item.risk_score ?? '--'))}</td>
        `;
        unifiedFindingsBody.appendChild(row);
    });
}

function renderUnifiedCorrelations(items) {
    if (!unifiedCorrelationsList) return;

    const list = Array.isArray(items) ? items : [];
    if (list.length === 0) {
        unifiedCorrelationsList.innerHTML = '<li>Sin correlaciones activas.</li>';
        return;
    }

    unifiedCorrelationsList.innerHTML = list
        .slice(0, 8)
        .map((item) => {
            const id = escapeHtml(item.id || 'UNKNOWN');
            const severity = escapeHtml(item.severity || 'UNKNOWN');
            const confidence = escapeHtml(String(item.confidence ?? '--'));
            const action = escapeHtml(item.action || 'ALERT');
            return `
                <li>
                    <div class="unified-correlations__id">${id}</div>
                    <div class="unified-correlations__meta">${severity} · Confianza ${confidence} · ${action}</div>
                </li>
            `;
        })
        .join('');
}

async function refreshUnifiedMonitor({ silent = false } = {}) {
    try {
        const [riskResponse, findingsResponse, correlationsResponse] = await Promise.all([
            apiFetch(API_V2_RISK),
            apiFetch(API_V2_FINDINGS),
            apiFetch(API_V2_CORRELATIONS),
        ]);

        const riskPayload = await riskResponse.json().catch(() => ({}));
        const findingsPayload = await findingsResponse.json().catch(() => ({}));
        const correlationsPayload = await correlationsResponse.json().catch(() => ({}));

        if (!riskResponse.ok || !findingsResponse.ok || !correlationsResponse.ok) {
            const message = riskPayload?.detail || findingsPayload?.detail || correlationsPayload?.detail || 'No se pudo cargar el monitor unificado.';
            throw new Error(message);
        }

        const risk = riskPayload.risk || {};
        const findings = Array.isArray(findingsPayload.items) ? findingsPayload.items : [];
        const correlations = Array.isArray(correlationsPayload.items) ? correlationsPayload.items : [];

        unifiedLatestFindings = findings;
        renderUnifiedRisk(risk);
        renderEndpointMetrics(risk.endpoint_features || {});
        renderUnifiedFindings(findings);
        renderUnifiedCorrelations(correlations);
    } catch (error) {
        if (!silent) {
            showError(error.message || 'Error cargando monitor anti-ransomware.');
        }
    }
}

async function runRemediationAction(action) {
    if (!remediationOutput) return;

    remediationOutput.textContent = 'Procesando...';

    try {
        if (action === 'preview') {
            // ── PREVIEW: return all vulnerabilities grouped by ID ────────────
            const response = await apiFetch(`${API_V2}/remediation/preview-all`);
            const payload = await response.json().catch(() => ({}));
            if (!response.ok) {
                throw new Error(payload?.detail || payload?.error || `Error HTTP ${response.status}`);
            }
            remediationOutput.textContent = JSON.stringify(payload, null, 2);

        } else {
            // ── EXECUTE: remediate ALL findings, reset score, re-scan ────────
            // Identify the IP that was last scanned so we only touch that lab.
            const scannedIp = targetInput?.value?.trim() || null;

            const response = await apiFetch(`${API_V2}/remediate-all`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    os_name: 'linux',
                    force: true,
                    target_ip: scannedIp,
                }),
            });
            const payload = await response.json().catch(() => ({}));
            if (!response.ok) {
                throw new Error(payload?.detail || payload?.error || `Error HTTP ${response.status}`);
            }

            remediationOutput.textContent =
                `Remediacion completada:\n` +
                `  Total findings: ${payload.total ?? '?'}\n` +
                `  Ejecutados:     ${payload.executed ?? '?'}\n` +
                `  Omitidos:       ${payload.skipped ?? '?'}\n\n` +
                JSON.stringify(payload.results ?? [], null, 2);

            // Refresh unified monitor (score should now be 0)
            await refreshUnifiedMonitor({ silent: true });

            // Auto relaunch deep scan so the UI reflects the fixed surface
            if (scannedIp) {
                setTimeout(() => {
                    remediationOutput.textContent += '\n\nRe-escaneando objetivo para verificar correcciones...';
                    launchDeepScan(scannedIp);
                }, 1500);
            }
        }
    } catch (error) {
        remediationOutput.textContent = `Error: ${error.message || 'fallo de remediación'}`;
    }
}

async function launchDeepScan(target) {
    // EN: Deep-scan request lifecycle.
    // do.
    showLoading('Escaneo profundo en curso...', `Analizando ${target}<br>nmap -A -sV --version-all -sC -O --osscan-guess -T4<br>Esto puede tardar 1-3 minutos`);
    hideError();
    try {
        const res = await apiFetch(API_SCAN, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || `Error del servidor (${res.status})`);
        }
        renderScanResults(await res.json());
    } catch (err) {
        showError(err.message);
    } finally {
        hideLoading();
    }
}

scanForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const target = targetInput.value.trim();
    if (!target) { targetInput.classList.add('input--error'); showError('Ingresa una IP objetivo'); setTimeout(() => targetInput.classList.remove('input--error'), 600); return; }
    if (!isValidIP(target)) { targetInput.classList.add('input--error'); showError('IP invalida. Formato: x.x.x.x'); setTimeout(() => targetInput.classList.remove('input--error'), 600); return; }
    launchDeepScan(target);
});
targetInput.addEventListener('input', () => targetInput.classList.remove('input--error'));

if (aiChatForm) {
    aiChatForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const userMessage = aiChatInput.value.trim();
        if (!userMessage) return;

        aiChatInput.value = '';
        await handleAIUserMessage(userMessage);
    });
}

if (aiQuickActions) {
    aiQuickActions.addEventListener('click', async (event) => {
        const button = event.target.closest('.btn-chat-action');
        if (!button) return;

        await handleAIQuickAction(button.dataset.action);
    });
}

if (unifiedRefreshBtn) {
    unifiedRefreshBtn.addEventListener('click', async () => {
        await refreshUnifiedMonitor({ silent: false });
    });
}

if (remediationPreviewBtn) {
    remediationPreviewBtn.addEventListener('click', async () => {
        await runRemediationAction('preview');
    });
}

if (remediationExecuteBtn) {
    remediationExecuteBtn.addEventListener('click', async () => {
        await runRemediationAction('execute');
    });
}

updateAISimulationHint();

bootstrapAIChat();

document.addEventListener('horus:session-ready', () => {
    if (!hasActiveSession()) return;

    checkAIStatus(true).catch(() => { });

    fetchSimulationHistory(1)
        .then((items) => {
            if (!Array.isArray(items) || items.length === 0) return;
            const latestId = Number.parseInt(String(items[0].id), 10);
            if (!Number.isFinite(latestId) || latestId <= 0) return;
            currentSimulationId = latestId;
            updateAISimulationHint();
        })
        .catch(() => { });

    refreshUnifiedMonitor({ silent: false }).catch(() => { });
});

setInterval(() => {
    refreshUnifiedMonitor({ silent: true }).catch(() => { });
}, 12000);
