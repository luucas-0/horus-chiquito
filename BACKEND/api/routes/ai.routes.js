import express from "express";
import {
    analyzeSingleSimulation,
    analyzeBatchSimulations,
    analyzeStoredSimulation,
    chatWithAIAgent,
    getAIStatus,
    downloadPDFReport,
    emailPDFReport,
    remediateSimulation
} from "../controllers/ai.controller.js";

const router = express.Router();

router.get("/status", getAIStatus);
router.post("/analyze", analyzeSingleSimulation);
router.post("/analyze/batch", analyzeBatchSimulations);
router.post("/analyze/simulation/:simulationId", analyzeStoredSimulation);
router.post("/chat", chatWithAIAgent);
router.get("/report/:simulationId/pdf", downloadPDFReport);
router.post("/report/:simulationId/email", emailPDFReport);
router.get("/remediation/:simulationId", remediateSimulation);

export default router;
