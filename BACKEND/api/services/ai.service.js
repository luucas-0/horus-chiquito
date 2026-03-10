import { getOpenAIClient, getOpenAIConfig, isOpenAIConfigured } from "../config/openai.config.js";
import {
    buildSystemPrompt,
    buildUserPrompt,
    validateSimulationData,
    sanitizeSimulationData
} from "../utils/aiPromptBuilder.js";
import {
    normalizeScanDataToMER,
    prepareDataForAIAnalysis,
    prepareAIAnalysisForStorage,
    validateNormalizedData
} from "../utils/dataNormalizer.js";

export async function analyzeWithAI(rawScanData) {
    if (!isOpenAIConfigured()) {
        throw new Error("OpenAI is not configured. Please set OPENAI_API_KEY in .env file.");
    }

    const basicValidation = validateSimulationData(rawScanData);
    if (!basicValidation.valid) {
        throw new Error(`Invalid simulation data: ${basicValidation.error}`);
    }

    const normalizedData = normalizeScanDataToMER(rawScanData);

    const merValidation = validateNormalizedData(normalizedData);
    if (!merValidation.valid) {
        throw new Error(`Invalid MER structure: ${merValidation.errors.join(", ")}`);
    }

    const aiReadyData = prepareDataForAIAnalysis(normalizedData);
    const sanitized = sanitizeSimulationData(aiReadyData);

    const systemPrompt = buildSystemPrompt();
    const userPrompt = buildUserPrompt(sanitized);

    const openai = await getOpenAIClient();
    const openaiConfig = getOpenAIConfig();

    let completion;

    try {
        completion = await openai.chat.completions.create({
            model: openaiConfig.model,
            temperature: openaiConfig.temperature,
            max_tokens: openaiConfig.maxTokens,
            messages: [
                {
                    role: "system",
                    content: systemPrompt
                },
                {
                    role: "user",
                    content: userPrompt
                }
            ],
            response_format: { type: "json_object" }
        });
    } catch (apiError) {
        throw new Error(`OpenAI API request failed: ${apiError.message}`);
    }

    const rawResponse = completion.choices[0]?.message?.content;

    if (!rawResponse) {
        throw new Error("OpenAI returned an empty response");
    }

    let parsedAnalysis;

    try {
        parsedAnalysis = JSON.parse(rawResponse);
    } catch {
        throw new Error("Failed to parse AI analysis response as JSON");
    }

    const standardAnalysis = {
        executive_summary: parsedAnalysis.executive_summary || "No summary available",
        overall_risk_score: parsedAnalysis.overall_risk_score || 0,
        risk_level: parsedAnalysis.risk_level || "UNKNOWN",
        scan_metadata: parsedAnalysis.scan_metadata || {},
        vulnerabilities: Array.isArray(parsedAnalysis.vulnerabilities) ? parsedAnalysis.vulnerabilities : [],
        network_exposure: parsedAnalysis.network_exposure || {},
        compliance_notes: parsedAnalysis.compliance_notes || {},
        immediate_actions: Array.isArray(parsedAnalysis.immediate_actions)
            ? parsedAnalysis.immediate_actions
            : [],
        analysis_confidence: parsedAnalysis.analysis_confidence || 0.0,
        generated_at: parsedAnalysis.generated_at || new Date().toISOString(),
        model_version: openaiConfig.model
    };

    const aiAnalysisMER = prepareAIAnalysisForStorage(standardAnalysis, normalizedData.simulation.id);

    return {
        ...standardAnalysis,
        _mer_metadata: {
            simulation_id: normalizedData.simulation.id,
            host_id: normalizedData.host.id,
            normalized_structure: {
                simulation: normalizedData.simulation,
                host: normalizedData.host,
                ports_count: normalizedData.ports.length,
                credential_tests_count: normalizedData.credentialTests.length,
                vulnerabilities_count: normalizedData.vulnerabilities.length
            },
            ai_analysis_storage: aiAnalysisMER
        }
    };
}

export async function batchAnalyze(simulationsArray) {
    if (!Array.isArray(simulationsArray) || simulationsArray.length === 0) {
        throw new Error("Batch analyze requires a non-empty array of simulations");
    }

    const results = [];
    const errors = [];

    for (let index = 0; index < simulationsArray.length; index += 1) {
        try {
            const analysis = await analyzeWithAI(simulationsArray[index]);
            results.push({
                index,
                success: true,
                analysis
            });
        } catch (error) {
            errors.push({
                index,
                success: false,
                error: error.message
            });
        }
    }

    return {
        total: simulationsArray.length,
        successful: results.length,
        failed: errors.length,
        results,
        errors
    };
}

const CHAT_SYSTEM_PROMPT = [
    "Eres HORUS, un agente de ciberseguridad para analizar hallazgos de escaneo de red.",
    "Responde SIEMPRE en espanol, con tono tecnico claro y accionable.",
    "Si falta informacion o contexto, dilo explicitamente y sugiere el siguiente paso.",
    "No inventes resultados de escaneo ni CVEs que no aparezcan en el contexto proporcionado.",
    "Si el usuario pide mitigaciones, entrega acciones priorizadas (inmediatas, corto plazo, mediano plazo).",
    "Si la pregunta no es de seguridad/escaneo, responde brevemente y redirige al objetivo del proyecto."
].join(" ");

function normalizeConversation(conversation) {
    if (!Array.isArray(conversation) || conversation.length === 0) {
        return [];
    }

    return conversation
        .slice(-8)
        .map((turn) => {
            const role = String(turn?.role || "").toLowerCase();
            const content = String(turn?.content || "").trim();

            if (!content || (role !== "user" && role !== "assistant")) {
                return null;
            }

            return {
                role,
                content: content.slice(0, 2000)
            };
        })
        .filter(Boolean);
}

function safeContextString(context) {
    if (!context || typeof context !== "object") {
        return null;
    }

    try {
        const json = JSON.stringify(context, null, 2);
        if (!json || json === "{}") {
            return null;
        }

        return json.length > 8000 ? `${json.slice(0, 8000)}\n... [context truncated]` : json;
    } catch {
        return null;
    }
}

export async function chatWithAIAgent({ message, conversation = [], context = null } = {}) {
    const userMessage = String(message || "").trim();

    if (!userMessage) {
        throw new Error("Message is required for AI chat");
    }

    if (!isOpenAIConfigured()) {
        throw new Error("OpenAI is not configured. Please set OPENAI_API_KEY in .env file.");
    }

    const openai = await getOpenAIClient();
    const openaiConfig = getOpenAIConfig();

    const contextJson = safeContextString(context);
    const historyMessages = normalizeConversation(conversation);

    const userPrompt = contextJson
        ? `Contexto tecnico disponible:\n${contextJson}\n\nPregunta del usuario:\n${userMessage}`
        : `Pregunta del usuario:\n${userMessage}`;

    let completion;

    try {
        completion = await openai.chat.completions.create({
            model: openaiConfig.model,
            temperature: Math.min(0.7, Math.max(0, openaiConfig.temperature + 0.05)),
            max_tokens: Math.min(openaiConfig.maxTokens, 1000),
            messages: [
                {
                    role: "system",
                    content: CHAT_SYSTEM_PROMPT
                },
                ...historyMessages,
                {
                    role: "user",
                    content: userPrompt
                }
            ]
        });
    } catch (apiError) {
        throw new Error(`OpenAI API request failed: ${apiError.message}`);
    }

    const reply = completion?.choices?.[0]?.message?.content?.trim();

    if (!reply) {
        throw new Error("OpenAI returned an empty chat response");
    }

    return {
        reply,
        model: openaiConfig.model,
        usage: completion?.usage || null
    };
}
