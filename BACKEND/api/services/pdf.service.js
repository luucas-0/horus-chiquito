async function getPdfKit() {
    const pdfModule = await import("pdfkit");
    return pdfModule.default || pdfModule;
}

export async function generatePDFReport(aiReport, simulationMeta) {
    try {
        if (!aiReport || typeof aiReport !== "object") {
            throw new Error("El analisis de IA es invalido o no existe");
        }

        const PDFDocument = await getPdfKit();

        const target = simulationMeta?.target || "Objetivo no especificado";
        const scanDate = simulationMeta?.scan_date
            ? new Date(simulationMeta.scan_date).toLocaleDateString("es-ES")
            : new Date().toLocaleDateString("es-ES");
        const projectName = simulationMeta?.project_name || "Evaluacion de Seguridad";

        const riskScore = Number.isFinite(Number(aiReport.risk_score)) ? Number(aiReport.risk_score) : 0;
        const riskCategory = getRiskCategory(riskScore);
        const riskColor = getSeverityColor(riskCategory.toLowerCase());

        const doc = new PDFDocument({
            size: "A4",
            margin: 50
        });

        const chunks = [];

        return await new Promise((resolve, reject) => {
            doc.on("data", (chunk) => chunks.push(chunk));
            doc.on("end", () => resolve(Buffer.concat(chunks)));
            doc.on("error", (err) => reject(err));

            // Portada
            doc
                .fillColor("#0f172a")
                .fontSize(24)
                .font("Helvetica-Bold")
                .text("HORUS SECURITY", { align: "center" });

            doc.moveDown(0.5);

            doc
                .fontSize(14)
                .font("Helvetica")
                .fillColor("#6b7280")
                .text("Reporte de Seguridad Cibernetica", { align: "center" });

            doc.moveDown(2);

            doc
                .fontSize(11)
                .fillColor("#374151")
                .text(`Proyecto: ${projectName}`)
                .moveDown(0.5)
                .text(`Objetivo analizado: ${target}`)
                .moveDown(0.5)
                .text(`Fecha de escaneo: ${scanDate}`);

            doc.moveDown(2);

            // Resumen ejecutivo
            doc
                .fontSize(18)
                .fillColor("#0f172a")
                .font("Helvetica-Bold")
                .text("Resumen Ejecutivo");

            doc.moveDown(0.5);

            doc
                .fontSize(11)
                .font("Helvetica")
                .fillColor("#374151")
                .text(String(aiReport.executive_summary || "Sin resumen disponible."), {
                    align: "justify"
                });

            doc.moveDown(1);

            // Indicador de riesgo
            const startY = doc.y + 10;
            doc
                .roundedRect(doc.x, startY, 260, 30, 6)
                .fillAndStroke(riskColor || "#3b82f6", "#e5e7eb");

            doc
                .fillColor("#ffffff")
                .fontSize(12)
                .font("Helvetica-Bold")
                .text(`Riesgo global: ${riskCategory.toUpperCase()} (${riskScore}/100)`, doc.x + 10, startY + 8);

            doc.moveDown(3);

            // Vulnerabilidades principales
            const vulnerabilities = Array.isArray(aiReport.vulnerabilities) ? aiReport.vulnerabilities : [];

            doc
                .fillColor("#0f172a")
                .fontSize(16)
                .font("Helvetica-Bold")
                .text("Vulnerabilidades Detectadas");

            doc.moveDown(0.3);

            doc
                .fontSize(9)
                .font("Helvetica")
                .fillColor("#6b7280")
                .text(
                    "Una vulnerabilidad es una debilidad en un sistema que podria ser aprovechada por " +
                    "un atacante para acceder sin autorizacion, robar informacion o causar danos. " +
                    "A continuacion se detallan los hallazgos encontrados con explicaciones claras sobre " +
                    "que significan, que impacto tienen y que acciones debe tomar.",
                    { align: "justify" }
                );

            doc.moveDown(0.5);

            if (vulnerabilities.length === 0) {
                doc
                    .fontSize(11)
                    .font("Helvetica")
                    .fillColor("#374151")
                    .text("No se detectaron vulnerabilidades durante el analisis.");
            } else {
                vulnerabilities.slice(0, 10).forEach((vuln, index) => {
                    const severity = String(vuln.severity || "medium").toLowerCase();
                    const color = getSeverityColor(severity);
                    const title = vuln.title || `Vulnerabilidad ${index + 1}`;
                    const component = vuln.affected_component || "Componente no especificado";

                    if (doc.y > 650) doc.addPage();

                    doc.moveDown(0.8);

                    doc
                        .fontSize(12)
                        .font("Helvetica-Bold")
                        .fillColor("#0f172a")
                        .text(`${index + 1}. ${title}`, { continued: true })
                        .fillColor(color)
                        .text(`  [${severity.toUpperCase()}]`);

                    doc
                        .fontSize(9)
                        .font("Helvetica")
                        .fillColor("#4b5563")
                        .text(`Componente afectado: ${component}`);

                    doc.moveDown(0.3);

                    if (vuln.plain_description) {
                        doc
                            .fontSize(9)
                            .font("Helvetica-Bold")
                            .fillColor("#1e3a5f")
                            .text("Que significa esto?");

                        doc
                            .font("Helvetica")
                            .fontSize(9)
                            .fillColor("#374151")
                            .text(String(vuln.plain_description), { align: "justify" });

                        doc.moveDown(0.2);
                    }

                    if (vuln.business_impact) {
                        doc
                            .fontSize(9)
                            .font("Helvetica-Bold")
                            .fillColor("#7f1d1d")
                            .text("Impacto para su organizacion:");

                        doc
                            .font("Helvetica")
                            .fontSize(9)
                            .fillColor("#991b1b")
                            .text(String(vuln.business_impact), { align: "justify" });

                        doc.moveDown(0.2);
                    }

                    if (vuln.what_to_do) {
                        doc
                            .fontSize(9)
                            .font("Helvetica-Bold")
                            .fillColor("#166534")
                            .text("Que debe hacer:");

                        doc
                            .font("Helvetica")
                            .fontSize(9)
                            .fillColor("#15803d")
                            .text(String(vuln.what_to_do), { align: "justify" });
                    }

                    if (vuln.description && !vuln.plain_description) {
                        doc
                            .moveDown(0.1)
                            .fontSize(9)
                            .font("Helvetica")
                            .fillColor("#374151")
                            .text(String(vuln.description), { align: "justify" });
                    }
                });
            }

            const recommendations = Array.isArray(aiReport.recommendations) ? aiReport.recommendations : [];
            const remediationActivity = Array.isArray(aiReport.remediation_activity) ? aiReport.remediation_activity : [];
            const remediationExecuted = remediationActivity.some((item) => Boolean(item?.executed));
            const remediationBlindajeExplanation = String(aiReport.remediation_blindaje_explanation || "").trim();

            if (remediationExecuted) {
                doc.addPage();

                doc
                    .fillColor("#0f172a")
                    .fontSize(16)
                    .font("Helvetica-Bold")
                    .text("Blindaje Aplicado por HORUS");

                doc.moveDown(0.4);

                doc
                    .fontSize(9)
                    .font("Helvetica")
                    .fillColor("#374151")
                    .text(
                        remediationBlindajeExplanation ||
                        "La herramienta ejecuto remediaciones para contener y cerrar la brecha detectada, reduciendo la superficie de ataque activa.",
                        { align: "justify" }
                    );
            } else {
                doc.addPage();

                // Recomendaciones
                doc
                    .fillColor("#0f172a")
                    .fontSize(16)
                    .font("Helvetica-Bold")
                    .text("Recomendaciones de Mitigacion");

                doc.moveDown(0.5);

                if (recommendations.length === 0) {
                    doc
                        .fontSize(11)
                        .font("Helvetica")
                        .fillColor("#374151")
                        .text("No se registraron recomendaciones especificas en el analisis.");
                } else {
                    recommendations.forEach((rec, index) => {
                        const title = rec.title || rec.action || `Recomendacion ${index + 1}`;
                        const description = rec.description || rec.details || "Sin detalles disponibles.";

                        doc
                            .moveDown(0.8)
                            .fontSize(11)
                            .font("Helvetica-Bold")
                            .fillColor("#166534")
                            .text(`${index + 1}. ${title}`);

                        doc
                            .moveDown(0.1)
                            .fontSize(9)
                            .font("Helvetica")
                            .fillColor("#15803d")
                            .text(String(description), { align: "justify" });
                    });
                }
            }

            if (remediationActivity.length > 0) {
                doc.addPage();

                doc
                    .fillColor("#0f172a")
                    .fontSize(16)
                    .font("Helvetica-Bold")
                    .text("Acciones de Remediacion Ejecutadas por HORUS");

                doc.moveDown(0.4);

                doc
                    .fontSize(9)
                    .font("Helvetica")
                    .fillColor("#374151")
                    .text(
                        "Esta seccion resume las acciones de remediacion registradas por la herramienta. " +
                        "Permite explicar que hizo HORUS para corregir o contener el problema detectado.",
                        { align: "justify" }
                    );

                remediationActivity.slice(0, 12).forEach((item, index) => {
                    if (doc.y > 690) {
                        doc.addPage();
                    }

                    const statusLabel = item.executed
                        ? "EJECUTADA"
                        : item.queued
                            ? "EN COLA"
                            : "REGISTRADA";

                    const statusColor = item.executed
                        ? "#166534"
                        : item.queued
                            ? "#92400e"
                            : "#1f2937";

                    const title = item.finding_type || "hallazgo";
                    const timestamp = item.timestamp
                        ? new Date(item.timestamp).toLocaleString("es-ES")
                        : "--";
                    const explanation = item.explanation || item.message || "Sin detalle.";
                    const commands = Array.isArray(item.commands) ? item.commands.filter(Boolean) : [];
                    const actions = Array.isArray(item.actions) ? item.actions.filter(Boolean) : [];

                    doc
                        .moveDown(0.8)
                        .fontSize(11)
                        .font("Helvetica-Bold")
                        .fillColor(statusColor)
                        .text(String(index + 1) + ". " + title + " [" + statusLabel + "]");

                    doc
                        .moveDown(0.1)
                        .fontSize(9)
                        .font("Helvetica")
                        .fillColor("#374151")
                        .text("Fecha: " + timestamp)
                        .text("Detalle: " + String(explanation), { align: "justify" });

                    if (commands.length > 0) {
                        doc
                            .moveDown(0.1)
                            .fontSize(9)
                            .font("Helvetica")
                            .fillColor("#1f2937")
                            .text("Comandos: " + commands.join(" | "), { align: "justify" });
                    }

                    if (actions.length > 0) {
                        doc
                            .moveDown(0.1)
                            .fontSize(9)
                            .font("Helvetica")
                            .fillColor("#1f2937")
                            .text("Acciones: " + actions.join(", "), { align: "justify" });
                    }
                });
            }

            doc.addPage();

            // Disclaimer
            doc
                .fontSize(13)
                .font("Helvetica-Bold")
                .fillColor("#78350f")
                .text("Aviso Legal y Disclaimer");

            doc.moveDown(0.5);

            const disclaimerText = [
                "Este reporte ha sido generado mediante un analisis automatizado de seguridad realizado por HORUS SECURITY.",
                "El uso de esta herramienta debe realizarse unicamente en sistemas sobre los cuales se tiene autorizacion explicita.",
                "El mal uso de este software puede violar leyes de ciberseguridad y privacidad.",
                "Si bien el analisis utiliza inteligencia artificial y herramientas especializadas, no garantiza la deteccion de todas las vulnerabilidades existentes.",
                "Se recomienda complementar este reporte con auditorias manuales realizadas por profesionales certificados.",
                "Este documento contiene informacion sensible sobre la seguridad del sistema analizado y debe tratarse de forma confidencial."
            ];

            doc
                .fontSize(9)
                .font("Helvetica")
                .fillColor("#92400e")
                .list(disclaimerText, { bulletRadius: 2 });

            doc.end();
        });
    } catch (error) {
        throw new Error(`Failed to generate PDF report: ${error.message}`);
    }
}

export function validateReportData(aiReport) {
    if (!aiReport.analysis_metadata) {
        return { valid: false, error: "Missing analysis_metadata" };
    }

    if (!aiReport.executive_summary) {
        return { valid: false, error: "Missing executive_summary" };
    }

    if (!Array.isArray(aiReport.vulnerabilities)) {
        return { valid: false, error: "Missing vulnerabilities array" };
    }

    if (!Array.isArray(aiReport.recommendations)) {
        return { valid: false, error: "Missing recommendations array" };
    }

    if (typeof aiReport.risk_score !== "number") {
        return { valid: false, error: "Missing or invalid risk_score" };
    }

    return { valid: true };
}

export function getRiskCategory(score) {
    if (score >= 80) return "Crítico";
    if (score >= 60) return "Alto";
    if (score >= 40) return "Medio";
    return "Bajo";
}

export function getSeverityColor(severity) {
    const colors = {
        low: "#22c55e",
        medium: "#f59e0b",
        high: "#ef4444",
        critical: "#991b1b"
    };

    return colors[String(severity || "").toLowerCase()] || "#6b7280";
}
