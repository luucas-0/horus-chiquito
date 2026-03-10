import { getRiskCategory, getSeverityColor } from "../services/pdf.service.js";

// HTML completo del reporte

export function buildReportHTML(aiReport, simulationMeta) {
    const {
        executive_summary,
        risk_score,
        vulnerabilities,
        recommendations,
        analysis_metadata,
    } = aiReport;

    // Valores por defecto si no vienen en simulationMeta
    const target = simulationMeta?.target || "Objetivo no especificado";
    const scanDate = simulationMeta?.scan_date
        ? new Date(simulationMeta.scan_date).toLocaleDateString("es-ES", {
              year: "numeric",
              month: "long",
              day: "numeric",
          })
        : new Date().toLocaleDateString("es-ES", {
              year: "numeric",
              month: "long",
              day: "numeric",
          });
    const projectName = simulationMeta?.project_name || "Evaluación de Seguridad";

    // Categoria del riesgo general
    const riskCategory = getRiskCategory(risk_score);
    const riskColor = getSeverityColor(riskCategory.toLowerCase());

    return `
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Seguridad - ${projectName}</title>
    <style>
        ${getReportStyles()}
    </style>
</head>
<body>
    ${buildCoverPage(projectName, target, scanDate)}
    ${buildExecutiveSummary(executive_summary, risk_score, riskCategory, riskColor)}
    ${buildVulnerabilitiesTable(vulnerabilities)}
    ${buildVulnerabilitiesDetails(vulnerabilities)}
    ${buildRecommendations(recommendations)}
    ${buildDisclaimer()}
</body>
</html>
    `;
}

// CSS global del reporte
// Estilos profesionales, limpios y estructurados
 
function getReportStyles() {
    return `
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            color: #1f2937;
            line-height: 1.6;
            background: #ffffff;
        }

        .cover-page {
            height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            text-align: center;
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            color: white;
            page-break-after: always;
        }

        .cover-page__icon {
            font-size: 80px;
            margin-bottom: 20px;
        }

        .cover-page__title {
            font-size: 48px;
            font-weight: 700;
            margin-bottom: 15px;
            letter-spacing: 2px;
        }

        .cover-page__subtitle {
            font-size: 22px;
            font-weight: 300;
            margin-bottom: 60px;
            color: #cbd5e1;
        }

        .cover-page__info {
            margin-top: 40px;
            font-size: 16px;
            color: #94a3b8;
        }

        .cover-page__info-item {
            margin: 10px 0;
        }

        .cover-page__info-label {
            font-weight: 600;
            color: #e2e8f0;
        }

        .section {
            padding: 40px 0;
            page-break-inside: avoid;
        }

        .section-title {
            font-size: 28px;
            font-weight: 700;
            color: #1e293b;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #3b82f6;
        }

        .section-subtitle {
            font-size: 20px;
            font-weight: 600;
            color: #475569;
            margin-top: 30px;
            margin-bottom: 15px;
        }

        .risk-indicator {
            display: inline-block;
            padding: 15px 30px;
            border-radius: 8px;
            font-size: 24px;
            font-weight: 700;
            color: white;
            margin: 20px 0;
        }

        .summary-text {
            font-size: 16px;
            line-height: 1.8;
            color: #374151;
            margin: 20px 0;
            text-align: justify;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 25px 0;
            font-size: 14px;
        }

        thead {
            background: #f1f5f9;
        }

        th {
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #1e293b;
            border-bottom: 2px solid #cbd5e1;
        }

        td {
            padding: 12px;
            border-bottom: 1px solid #e2e8f0;
        }

        tbody tr:hover {
            background: #f8fafc;
        }

        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            color: white;
            text-transform: uppercase;
        }

        .vulnerability-detail {
            margin: 30px 0;
            padding: 20px;
            background: #f8fafc;
            border-left: 4px solid #3b82f6;
            page-break-inside: avoid;
        }

        .vulnerability-detail__title {
            font-size: 18px;
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 10px;
        }

        .vulnerability-detail__description {
            font-size: 14px;
            line-height: 1.7;
            color: #475569;
            margin: 10px 0;
        }

        .vulnerability-detail__impact {
            margin-top: 15px;
            padding: 12px;
            background: white;
            border-radius: 6px;
        }

        .vulnerability-detail__label {
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 5px;
            display: block;
        }

        .recommendation-item {
            margin: 20px 0;
            padding: 15px;
            background: #f0fdf4;
            border-left: 4px solid #22c55e;
            page-break-inside: avoid;
        }

        .recommendation-item__title {
            font-size: 16px;
            font-weight: 600;
            color: #166534;
            margin-bottom: 8px;
        }

        .recommendation-item__description {
            font-size: 14px;
            line-height: 1.7;
            color: #15803d;
        }

        .disclaimer {
            margin-top: 50px;
            padding: 20px;
            background: #fef3c7;
            border: 1px solid #fbbf24;
            border-radius: 6px;
            font-size: 11px;
            color: #78350f;
            line-height: 1.6;
        }

        .disclaimer__title {
            font-weight: 700;
            margin-bottom: 10px;
            font-size: 13px;
        }

        .page-break {
            page-break-before: always;
        }
    `;
}

// Portada del reporte

function buildCoverPage(projectName, target, scanDate) {
    return `
        <div class="cover-page">
            <div class="cover-page__icon">𓂀</div>
            <h1 class="cover-page__title">HORUS SECURITY</h1>
            <p class="cover-page__subtitle">Reporte de Seguridad Cibernética</p>
            <div class="cover-page__info">
                <div class="cover-page__info-item">
                    <span class="cover-page__info-label">Proyecto:</span> ${escapeHtml(projectName)}
                </div>
                <div class="cover-page__info-item">
                    <span class="cover-page__info-label">Objetivo Analizado:</span> ${escapeHtml(target)}
                </div>
                <div class="cover-page__info-item">
                    <span class="cover-page__info-label">Fecha de Escaneo:</span> ${scanDate}
                </div>
            </div>
        </div>
    `;
}

// Seccion de resumen ejecutivo

function buildExecutiveSummary(summary, riskScore, riskCategory, riskColor) {
    return `
        <div class="section">
            <h2 class="section-title">Resumen Ejecutivo</h2>
            <p class="summary-text">
                ${escapeHtml(summary)}
            </p>
            <h3 class="section-subtitle">Nivel de Riesgo General</h3>
            <div class="risk-indicator" style="background-color: ${riskColor};">
                ${riskCategory.toUpperCase()} (${riskScore}/100)
            </div>
            <p class="summary-text">
                Este puntaje refleja la severidad general de las vulnerabilidades detectadas en el sistema objetivo.
                Un puntaje más alto indica una mayor exposición a amenazas de seguridad.
            </p>
        </div>
    `;
}

// Tabla resumen de vulnerabilidades

function buildVulnerabilitiesTable(vulnerabilities) {
    if (!vulnerabilities || vulnerabilities.length === 0) {
        return `
            <div class="section page-break">
                <h2 class="section-title">Vulnerabilidades Detectadas</h2>
                <p class="summary-text">No se detectaron vulnerabilidades durante el análisis.</p>
            </div>
        `;
    }

    const tableRows = vulnerabilities
        .map((vuln) => {
            const severity = vuln.severity || "medium";
            const color = getSeverityColor(severity);
            return `
                <tr>
                    <td>${escapeHtml(vuln.title || "Sin título")}</td>
                    <td>
                        <span class="severity-badge" style="background-color: ${color};">
                            ${severity.toUpperCase()}
                        </span>
                    </td>
                    <td>${escapeHtml(vuln.affected_component || "N/A")}</td>
                </tr>
            `;
        })
        .join("");

    return `
        <div class="section page-break">
            <h2 class="section-title">Tabla de Vulnerabilidades</h2>
            <table>
                <thead>
                    <tr>
                        <th>Vulnerabilidad</th>
                        <th>Severidad</th>
                        <th>Componente Afectado</th>
                    </tr>
                </thead>
                <tbody>
                    ${tableRows}
                </tbody>
            </table>
        </div>
    `;
}

// Seccion detallada de cada vulnerabilidad

function buildVulnerabilitiesDetails(vulnerabilities) {
    if (!vulnerabilities || vulnerabilities.length === 0) {
        return "";
    }

    const detailsHTML = vulnerabilities
        .map((vuln, index) => {
            const severity = vuln.severity || "medium";
            const color = getSeverityColor(severity);

            return `
                <div class="vulnerability-detail" style="border-left-color: ${color};">
                    <div class="vulnerability-detail__title">
                        ${index + 1}. ${escapeHtml(vuln.title || "Vulnerabilidad sin título")}
                    </div>
                    <div class="vulnerability-detail__description">
                        <span class="vulnerability-detail__label">Descripción:</span>
                        ${escapeHtml(vuln.description || "Sin descripción disponible")}
                    </div>
                    <div class="vulnerability-detail__impact">
                        <span class="vulnerability-detail__label">Impacto Potencial:</span>
                        ${escapeHtml(vuln.impact || "Sin información de impacto")}
                    </div>
                    ${
                        vuln.cve_id
                            ? `
                        <div class="vulnerability-detail__description" style="margin-top: 10px;">
                            <span class="vulnerability-detail__label">CVE ID:</span>
                            ${escapeHtml(vuln.cve_id)}
                        </div>
                    `
                            : ""
                    }
                </div>
            `;
        })
        .join("");

    return `
        <div class="section page-break">
            <h2 class="section-title">Detalles de Vulnerabilidades</h2>
            ${detailsHTML}
        </div>
    `;
}

// Seccion de recomendaciones

function buildRecommendations(recommendations) {
    if (!recommendations || recommendations.length === 0) {
        return "";
    }

    const recommendationsHTML = recommendations
        .map((rec, index) => {
            return `
                <div class="recommendation-item">
                    <div class="recommendation-item__title">
                        ${index + 1}. ${escapeHtml(rec.title || rec.action || "Recomendación")}
                    </div>
                    <div class="recommendation-item__description">
                        ${escapeHtml(rec.description || rec.details || "Sin detalles disponibles")}
                    </div>
                </div>
            `;
        })
        .join("");

    return `
        <div class="section page-break">
            <h2 class="section-title">Recomendaciones de Mitigación</h2>
            <p class="summary-text">
                Las siguientes acciones le ayudarán a reducir los riesgos identificados en su infraestructura:
            </p>
            ${recommendationsHTML}
        </div>
    `;
}

// Disclaimer legal

function buildDisclaimer() {
    return `
        <div class="section">
            <div class="disclaimer">
                <div class="disclaimer__title">⚠️ AVISO LEGAL Y DISCLAIMER</div>
                <p>
                    Este reporte ha sido generado mediante un análisis automatizado de seguridad realizado por 
                    <strong>HORUS SECURITY</strong>. La información contenida en este documento tiene fines
                    // educativos y de evaluación de seguridad.
                </p>
                <p style="margin-top: 10px;">
                    <strong>Responsabilidad:</strong> El uso de esta herramienta debe realizarse únicamente en sistemas
                    // sobre los cuales se tiene autorización explícita. El mal uso de este software puede violar leyes de
                    // ciberseguridad y privacidad. Los autores no se hacen responsables del uso indebido de esta herramienta.
                </p>
                <p style="margin-top: 10px;">
                    <strong>Precisión:</strong> Si bien el análisis utiliza inteligencia artificial y herramientas 
                    // especializadas, no garantiza la detección de todas las vulnerabilidades existentes. Se recomienda
                    // complementar este reporte con auditorías manuales realizadas por profesionales certificados.
                </p>
                <p style="margin-top: 10px;">
                    <strong>Confidencialidad:</strong> Este documento contiene información sensible sobre la seguridad
                    // del sistema analizado. Debe ser tratado de forma confidencial y compartido únicamente con personal
                    // autorizado.
                </p>
            </div>
        </div>
    `;
}


// Escapa caracteres HTML para prevenir XSS
// (aunque el PDF no ejecuta JS, es buena práctica)

function escapeHtml(text) {
    if (!text) return "";
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
