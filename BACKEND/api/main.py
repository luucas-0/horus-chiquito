"""Unified FastAPI service for network + endpoint security platform."""

from __future__ import annotations

import asyncio
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field


BACKEND_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BACKEND_DIR.parent
AI_ORCHESTRATOR_DIR = BACKEND_DIR / "ai-orchestrator"

for candidate in (BACKEND_DIR, AI_ORCHESTRATOR_DIR, PROJECT_ROOT):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))


def _load_env_file(env_path: Path) -> None:
    """Load KEY=VALUE pairs from .env file without overriding existing env."""

    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", maxsplit=1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if key and key not in os.environ:
            os.environ[key] = value


import os  # noqa: E402  # placed after sys.path setup intentionally

_load_env_file(BACKEND_DIR / "api" / ".env")

from engine.analysis_engine import AnalysisEngine  # noqa: E402


class NetworkScanRequest(BaseModel):
    """Payload for launching a network scan."""

    target: str = Field(..., description="Target IPv4/IPv6 address or hostname")
    profile: str = Field(default="fast", description="Scan profile: fast, balanced, full")


class RemediationRequest(BaseModel):
    """Payload for executing remediation."""

    os_name: str = Field(default="linux", description="Target operating system key")
    force: bool = Field(default=False, description="Force execution for approval-gated playbooks")


class BulkRemediationRequest(BaseModel):
    """Payload for bulk remediation of all findings."""

    os_name: str = Field(default="linux", description="Target operating system key")
    force: bool = Field(default=True, description="Force execution for all findings")
    target_ip: str | None = Field(default=None, description="Restrict lab enforcement to this IP only")


class AgentEventRequest(BaseModel):
    """Payload ingested from endpoint agent telemetry."""

    action: str
    path: str | None = None
    extension_after: str | None = None
    process_pid: int | None = None
    entropy_before: float | None = None
    entropy_after: float | None = None
    process_is_signed: bool | None = None
    process_has_network_access: bool | None = None
    process_spawned_by_suspicious: bool | None = None
    process_age_seconds: float | None = None
    api_crypto_calls: float | None = None
    honeypot_touched: bool | None = None
    honeypot_modified: bool | None = None
    vss_delete_attempt: bool | None = None
    backup_path_access: bool | None = None


class EventHub:
    """WebSocket broadcast hub for real-time event stream."""

    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._clients.add(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(websocket)

    async def broadcast(self, payload: dict[str, Any]) -> None:
        async with self._lock:
            clients = list(self._clients)

        if not clients:
            return

        stale: list[WebSocket] = []
        for client in clients:
            try:
                await client.send_json(payload)
            except Exception:
                stale.append(client)

        if stale:
            async with self._lock:
                for websocket in stale:
                    self._clients.discard(websocket)


app = FastAPI(title="Unified Security Platform API", version="2.0.0")
event_hub = EventHub()
_event_loop: asyncio.AbstractEventLoop | None = None


def _publish_from_engine(payload: dict[str, Any]) -> None:
    """Bridge synchronous engine callback to async websocket hub."""

    if _event_loop is None:
        return
    asyncio.run_coroutine_threadsafe(event_hub.broadcast(payload), _event_loop)


analysis_engine = AnalysisEngine(event_callback=_publish_from_engine)


@app.on_event("startup")
async def on_startup() -> None:
    """Capture active event loop at startup for thread-safe broadcasts."""

    global _event_loop
    _event_loop = asyncio.get_running_loop()


@app.post("/api/v2/scan/network")
async def launch_network_scan(request: NetworkScanRequest) -> dict[str, Any]:
    """Launch a Nmap+Hydra network scan under unified engine."""

    scan_id = analysis_engine.start_network_scan(target=request.target, profile_name=request.profile)
    return {
        "scan_id": scan_id,
        "status": "queued",
        "target": request.target,
        "profile": request.profile,
        "requested_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/v2/scan/status/{scan_id}")
async def get_scan_status(scan_id: str) -> dict[str, Any]:
    """Get status of an in-progress or completed scan."""

    status = analysis_engine.get_scan_status(scan_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return status


@app.get("/api/v2/findings")
async def get_findings() -> dict[str, Any]:
    """Return all findings from network + endpoint + correlation sources."""

    findings = analysis_engine.get_findings()
    return {"count": len(findings), "items": findings}


@app.get("/api/v2/risk-score")
async def get_risk_score() -> dict[str, Any]:
    """Return latest unified risk score state."""

    risk = analysis_engine.get_risk_score()
    diagnostics = asdict(analysis_engine.inference.diagnostics())
    return {"risk": risk, "inference": diagnostics}


@app.get("/api/v2/risk-explanation")
async def get_risk_explanation() -> dict[str, Any]:
    """Return explainable risk diagnostics in human-readable form."""

    diagnostics = asdict(analysis_engine.inference.diagnostics())
    explanation = analysis_engine.get_risk_explanation()
    return {"explanation": explanation, "inference": diagnostics}


@app.post("/api/v2/remediate/{finding_id}")
async def remediate_finding(finding_id: str, request: RemediationRequest) -> dict[str, Any]:
    """Execute or queue remediation for finding."""

    result = analysis_engine.remediate(
        finding_id,
        os_name=request.os_name,
        force=request.force,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return result


@app.get("/api/v2/remediation/preview/{finding_id}")
async def remediation_preview(finding_id: str) -> dict[str, Any]:
    """Return remediation dry-run preview without execution."""

    preview = analysis_engine.remediation_preview(finding_id)
    if preview is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return preview


@app.get("/api/v2/remediation/preview-all")
async def remediation_preview_all() -> dict[str, Any]:
    """Return remediation preview for every current finding in one call."""

    previews = analysis_engine.preview_all()
    return {"count": len(previews), "items": previews}


@app.post("/api/v2/remediate-all")
async def remediate_all(request: BulkRemediationRequest) -> dict[str, Any]:
    """Remediate all current findings and reset engine state.

    Only applies lab enforcement to findings matching ``target_ip``
    so other lab containers are never touched.
    """

    results = analysis_engine.remediate_all(
        os_name=request.os_name,
        force=request.force,
        target_ip=request.target_ip,
    )
    executed = sum(1 for r in results if r.get("executed"))
    skipped = sum(1 for r in results if r.get("skipped"))
    return {
        "status": "completed",
        "total": len(results),
        "executed": executed,
        "skipped": skipped,
        "results": results,
    }


@app.post("/api/v2/reset-state")
async def reset_engine_state() -> dict[str, Any]:
    """Manually clear all in-memory findings, events, and risk scores."""

    analysis_engine.reset_state()
    return {"status": "reset", "message": "Engine state cleared."}


@app.post("/api/v2/agent/event")
async def ingest_agent_event(payload: AgentEventRequest) -> dict[str, Any]:
    """Ingest local endpoint event into unified analysis engine."""

    risk = analysis_engine.ingest_agent_event(payload.model_dump(exclude_none=True))
    return {"status": "accepted", "risk": risk}


@app.get("/api/v2/correlations")
async def get_correlations() -> dict[str, Any]:
    """Return current correlation alerts list."""

    alerts = analysis_engine.get_correlation_alerts()
    return {"count": len(alerts), "items": alerts}


@app.websocket("/api/v2/ws/stream")
async def stream_events(websocket: WebSocket) -> None:
    """WebSocket endpoint for real-time unified security events."""

    await event_hub.connect(websocket)
    await websocket.send_json({"type": "connected", "message": "unified stream ready"})

    try:
        while True:
            message = await websocket.receive_text()
            if message.lower() == "ping":
                await websocket.send_json({"type": "pong", "ts": datetime.now(timezone.utc).isoformat()})
    except WebSocketDisconnect:
        await event_hub.disconnect(websocket)
    except Exception:
        await event_hub.disconnect(websocket)
