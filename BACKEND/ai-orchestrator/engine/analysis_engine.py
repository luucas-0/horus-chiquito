"""Central analysis engine for unified network and endpoint security."""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import ipaddress
import os
from pathlib import Path
import threading
import time
from typing import Any, Callable, Mapping
from uuid import uuid4

from engine.correlation_rules import CorrelationAlert, CorrelationEngine
from engine.ml.feature_extractor import (
    ENDPOINT_FEATURES,
    MASS_ENCRYPTION_DELTA_THRESHOLD,
    MASS_ENCRYPTION_ENTROPY_THRESHOLD,
    MASS_FILE_WRITE_THRESHOLD,
    extract_correlation_features,
    extract_endpoint_features,
    extract_network_features,
)
from engine.ml.inference import RealTimeInference
from engine.remediation_engine import RemediationEngine
from engine.risk_scorer import RiskScoreBreakdown, UnifiedRiskScorer
from parsers.hydra_parser import HydraParser, HydraServiceResult
from scanner.docker_scanner import DockerScanner
from scanner.scan_profiles import get_scan_profile


@dataclass
class Finding:
    """Normalized finding from network, endpoint, or correlation sources."""

    id: str
    source: str
    finding_type: str
    severity: str
    confidence: float
    risk_score: int
    status: str
    created_at: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanJob:
    """State of a network scan job."""

    scan_id: str
    target: str
    profile: str
    status: str
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    error: str | None = None
    finding_ids: list[str] = field(default_factory=list)
    executed_commands: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class RiskState:
    """Current unified risk state."""

    score: int = 0
    endpoint_score: float = 0.0
    network_score: float = 0.0
    correlation_bonus: float = 0.0
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AnalysisEngine:
    """Coordinates scanner outputs, endpoint telemetry, correlation, and remediation."""

    def __init__(self, event_callback: Callable[[dict[str, Any]], None] | None = None) -> None:
        self.scanner = DockerScanner()
        self.inference = RealTimeInference()
        self.risk_scorer = UnifiedRiskScorer()
        self.remediation = RemediationEngine()

        correlation_rules_path = os.getenv("CORRELATION_RULES_PATH") or str(Path(__file__).resolve().with_name("correlation_rules.json"))
        self.correlation_engine = CorrelationEngine.from_json_file(correlation_rules_path)

        self._event_callback = event_callback
        self._lock = threading.RLock()

        self._scan_jobs: dict[str, ScanJob] = {}
        self._findings: list[Finding] = []
        self._correlation_alerts: list[CorrelationAlert] = []

        endpoint_buffer_size = max(500, int(os.getenv("ENDPOINT_EVENT_BUFFER_SIZE", "5000")))
        self._endpoint_events: deque[dict[str, Any]] = deque(maxlen=endpoint_buffer_size)
        self._latest_endpoint_features: dict[str, float | int | bool] = {
            key: False if value_type is bool else 0.0 if value_type is float else 0
            for key, value_type in ENDPOINT_FEATURES.items()
        }
        self._latest_network_features: dict[str, float | int | bool] = {}
        self._latest_endpoint_score_0_100 = 0.0
        self._latest_network_score_0_100 = 0.0
        self._risk_state = RiskState()
        self._mass_file_write_threshold = MASS_FILE_WRITE_THRESHOLD
        self._mass_entropy_threshold = MASS_ENCRYPTION_ENTROPY_THRESHOLD
        self._mass_entropy_delta_threshold = MASS_ENCRYPTION_DELTA_THRESHOLD
        self._dedup_window_seconds = max(5.0, float(os.getenv("FINDING_DEDUP_WINDOW_SECONDS", "30")))
        self._finding_last_seen_monotonic: dict[str, float] = {}

    def start_network_scan(self, target: str, profile_name: str | None = None) -> str:
        """Queue and start a network scan asynchronously."""

        profile = get_scan_profile(profile_name)
        scan_id = str(uuid4())
        job = ScanJob(
            scan_id=scan_id,
            target=target,
            profile=profile.name,
            status="queued",
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        with self._lock:
            self._scan_jobs[scan_id] = job

        worker = threading.Thread(target=self._run_scan_job, args=(scan_id,), daemon=True)
        worker.start()

        self._publish_event({"type": "scan_queued", "scan_id": scan_id, "target": target, "profile": profile.name})
        return scan_id

    def get_scan_status(self, scan_id: str) -> dict[str, Any] | None:
        """Return status payload for one scan job."""

        with self._lock:
            job = self._scan_jobs.get(scan_id)
            return asdict(job) if job else None

    def get_findings(self) -> list[dict[str, Any]]:
        """Return all findings sorted by recency."""

        with self._lock:
            ordered = sorted(self._findings, key=lambda item: item.created_at, reverse=True)
            return [asdict(item) for item in ordered]

    def get_correlation_alerts(self) -> list[dict[str, Any]]:
        """Return last evaluated correlation alerts."""

        with self._lock:
            return [asdict(alert) for alert in self._correlation_alerts]

    def get_risk_score(self) -> dict[str, Any]:
        """Return latest unified risk score state."""

        with self._lock:
            risk_payload = asdict(self._risk_state)
            risk_payload["endpoint_features"] = dict(self._latest_endpoint_features)
            risk_payload["network_features"] = dict(self._latest_network_features)
            return risk_payload

    def get_risk_explanation(self) -> dict[str, Any]:
        """Return a human-readable explanation for current risk and correlations."""

        with self._lock:
            risk_state = asdict(self._risk_state)
            endpoint_features = dict(self._latest_endpoint_features)
            network_features = dict(self._latest_network_features)
            correlation_flags = extract_correlation_features(
                endpoint_features=endpoint_features,
                network_features=network_features,
                multiple_hosts_affected=int(network_features.get("hosts_with_smb_open", 0)) > 1,
            )
            alerts = [asdict(alert) for alert in self._correlation_alerts]

        top_reasons = self._build_top_reasons(endpoint_features, network_features, correlation_flags)
        status = self._risk_status_text(int(risk_state.get("score", 0)))

        return {
            "risk": risk_state,
            "status": status,
            "summary": self._risk_summary_text(status=status, score=int(risk_state.get("score", 0))),
            "top_reasons": top_reasons,
            "active_flags": {
                "count": sum(1 for value in correlation_flags.values() if bool(value)),
                "items": [name for name, value in correlation_flags.items() if bool(value)],
            },
            "correlations": [self._explain_alert(alert) for alert in alerts],
            "suggested_actions": self._build_suggested_actions(status, endpoint_features, network_features, alerts),
        }

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        """Return one finding by exact ID or by unique ID prefix."""

        lookup = finding_id.strip()
        if not lookup:
            return None

        with self._lock:
            for finding in self._findings:
                if finding.id == lookup:
                    return asdict(finding)

            # UI shows a shortened ID. Accept prefix only when it is unambiguous.
            prefix_matches = [finding for finding in self._findings if finding.id.startswith(lookup)]
            if len(prefix_matches) == 1:
                return asdict(prefix_matches[0])
        return None

    def remediation_preview(self, finding_id: str) -> dict[str, Any] | None:
        """Return remediation preview for finding ID."""

        finding = self.get_finding(finding_id)
        if not finding:
            return None

        preview = self.remediation.preview_for_finding(finding)
        return asdict(preview)

    def remediate(
        self,
        finding_id: str,
        *,
        os_name: str,
        force: bool = False,
    ) -> dict[str, Any] | None:
        """Execute or queue remediation for a finding."""

        finding = self.get_finding(finding_id)
        if not finding:
            return None

        execution = self.remediation.execute_for_finding(
            finding,
            os_name=os_name,
            force=force,
            auto_remediation_enabled=os.getenv("AUTO_REMEDIATION", "false").lower() == "true",
        )
        payload = asdict(execution)
        self._publish_event({"type": "remediation", **payload})
        return payload

    def preview_all(self) -> list[dict[str, Any]]:
        """Return a preview for every current finding."""

        with self._lock:
            findings_snapshot = [asdict(f) for f in self._findings]

        return [
            {**asdict(self.remediation.preview_for_finding(f)), "finding_id": f["id"]}
            for f in findings_snapshot
        ]

    def remediate_all(
        self,
        *,
        os_name: str,
        force: bool = False,
        target_ip: str | None = None,
    ) -> list[dict[str, Any]]:
        """Execute remediation for all current findings and reset engine state.

        Args:
            os_name: Target OS for command selection.
            force: Bypass approval gates.
            target_ip: When provided, only lab-enforce on findings whose
                       ``details.target`` matches this IP (isolation guard).
        """

        with self._lock:
            findings_snapshot = [asdict(f) for f in self._findings]

        results: list[dict[str, Any]] = []
        auto_enabled = os.getenv("AUTO_REMEDIATION", "false").lower() == "true"

        for finding in findings_snapshot:
            # Isolation: for lab enforcement skip findings from other targets.
            finding_target = str(
                (finding.get("details") or {}).get("target", "")
            ).strip()
            if target_ip and finding_target and finding_target != target_ip:
                results.append({
                    "finding_id": finding["id"],
                    "finding_type": finding.get("finding_type"),
                    "skipped": True,
                    "reason": f"target mismatch ({finding_target} != {target_ip})",
                })
                continue

            execution = self.remediation.execute_for_finding(
                finding,
                os_name=os_name,
                force=force,
                auto_remediation_enabled=auto_enabled,
            )
            payload = asdict(execution)
            payload["finding_type"] = finding.get("finding_type")
            results.append(payload)
            self._publish_event({"type": "remediation", **payload})

        # Reset engine state so the next scan starts with a clean slate.
        self.reset_state()
        return results

    def reset_state(self) -> None:
        """Clear all in-memory findings, events, and risk scores.

        Called automatically after a successful remediate_all so that a
        subsequent scan reflects the post-remediation surface.
        """

        with self._lock:
            self._findings.clear()
            self._endpoint_events.clear()
            self._correlation_alerts.clear()
            self._finding_last_seen_monotonic.clear()
            self._latest_endpoint_features = {
                key: False if value_type is bool else 0.0 if value_type is float else 0
                for key, value_type in ENDPOINT_FEATURES.items()
            }
            self._latest_network_features = {}
            self._latest_endpoint_score_0_100 = 0.0
            self._latest_network_score_0_100 = 0.0
            self._risk_state = RiskState()

        self._publish_event({"type": "state_reset", "message": "Engine state cleared after remediation."})

    def ingest_agent_event(self, event: Mapping[str, Any]) -> dict[str, Any]:
        """Ingest one endpoint event from local agent."""

        event_payload = dict(event)
        event_payload.setdefault("timestamp", datetime.now(timezone.utc).isoformat())

        with self._lock:
            self._endpoint_events.append(event_payload)
            endpoint_features = extract_endpoint_features(self._endpoint_events)
            self._latest_endpoint_features = endpoint_features

            endpoint_probability = self.inference.score_endpoint_event(endpoint_features)
            self._latest_endpoint_score_0_100 = endpoint_probability * 100.0

            self._emit_endpoint_findings(event_payload, endpoint_features)
            self._refresh_correlation_and_risk_locked()

            risk = {
                **asdict(self._risk_state),
                "endpoint_features": dict(self._latest_endpoint_features),
                "network_features": dict(self._latest_network_features),
            }

        self._publish_event({"type": "agent_event", "event": event_payload, "risk": risk})
        return risk

    def _run_scan_job(self, scan_id: str) -> None:
        with self._lock:
            job = self._scan_jobs[scan_id]
            job.status = "running"
            job.started_at = datetime.now(timezone.utc).isoformat()

        self._publish_event({"type": "scan_started", "scan_id": scan_id, "target": job.target})

        profile = get_scan_profile(job.profile)

        try:
            artifacts = self.scanner.scan_target(job.target, profile)

            hydra_results: list[HydraServiceResult] = []
            for key, raw_output in artifacts.hydra_raw_outputs.items():
                service, port_text = key.split(":", maxsplit=1)
                hydra_results.append(HydraParser.parse(raw_output, service=service, port=int(port_text)))

            target_public = self._is_public_ip(job.target)
            network_features = extract_network_features(
                artifacts.nmap_result,
                hydra_results,
                target_is_public=target_public,
            )
            network_score = self.inference.score_network_features(network_features)

            with self._lock:
                self._latest_network_features = network_features
                self._latest_network_score_0_100 = network_score

                finding_ids = self._emit_network_findings(artifacts, hydra_results, network_features)
                job.finding_ids.extend(finding_ids)
                job.executed_commands = [asdict(command) for command in artifacts.executed_commands]

                self._refresh_correlation_and_risk_locked()

                job.status = "completed"
                job.completed_at = datetime.now(timezone.utc).isoformat()

            self._publish_event({
                "type": "scan_completed",
                "scan_id": scan_id,
                "target": job.target,
                "findings": len(finding_ids),
                "network_score": network_score,
            })
        except Exception as error:
            with self._lock:
                failed = self._scan_jobs[scan_id]
                failed.status = "failed"
                failed.error = str(error)
                failed.completed_at = datetime.now(timezone.utc).isoformat()

            self._publish_event({"type": "scan_failed", "scan_id": scan_id, "error": str(error)})

    def _emit_network_findings(
        self,
        artifacts: Any,
        hydra_results: list[HydraServiceResult],
        network_features: Mapping[str, float | int | bool],
    ) -> list[str]:
        finding_ids: list[str] = []

        def add_finding(finding_type: str, severity: str, confidence: float, risk_score: int, details: Mapping[str, Any]) -> None:
            finding = Finding(
                id=str(uuid4()),
                source="network",
                finding_type=finding_type,
                severity=severity,
                confidence=confidence,
                risk_score=risk_score,
                status="open",
                created_at=datetime.now(timezone.utc).isoformat(),
                details=dict(details),
            )
            self._findings.append(finding)
            finding_ids.append(finding.id)

        if int(network_features.get("open_critical_ports_count", 0)) > 0:
            add_finding(
                "open_critical_ports",
                "HIGH",
                0.85,
                70,
                {
                    "open_critical_ports_count": int(network_features.get("open_critical_ports_count", 0)),
                    "target": artifacts.target,
                },
            )

        if bool(network_features.get("smb_v1_enabled", False)):
            add_finding("smb_v1_enabled", "CRITICAL", 0.92, 90, {"target": artifacts.target})

        if bool(network_features.get("rdp_exposed_public", False)):
            add_finding("rdp_no_nla", "HIGH", 0.78, 75, {"target": artifacts.target})

        if int(network_features.get("unencrypted_services_count", 0)) > 0:
            add_finding(
                "telnet_open",
                "MEDIUM",
                0.7,
                55,
                {
                    "unencrypted_services_count": int(network_features.get("unencrypted_services_count", 0)),
                    "target": artifacts.target,
                },
            )

        weak_creds = [result for result in hydra_results if result.status == "credentials_found"]
        if weak_creds:
            add_finding(
                "weak_credentials",
                "CRITICAL",
                0.93,
                95,
                {
                    "services": [result.service for result in weak_creds],
                    "target": artifacts.target,
                },
            )

        return finding_ids

    def _emit_endpoint_findings(
        self,
        event_payload: Mapping[str, Any],
        endpoint_features: Mapping[str, float | int | bool],
    ) -> None:
        action = str(event_payload.get("action", "")).lower()
        modified_per_second = float(endpoint_features.get("files_modified_per_second", 0.0))
        entropy_avg = float(endpoint_features.get("entropy_avg_modified_files", 0.0))
        entropy_delta = float(endpoint_features.get("entropy_delta", 0.0))

        looks_mass_write = action == "modified" and modified_per_second >= self._mass_file_write_threshold
        looks_mass_encryption = (
            entropy_avg >= self._mass_entropy_threshold
            and entropy_delta >= self._mass_entropy_delta_threshold
        )

        if (action in {"modified", "created"}) and (looks_mass_write or looks_mass_encryption):
            path = str(event_payload.get("path", "unknown"))
            fingerprint = f"endpoint:mass_encryption:{path}"
            if self._should_emit_finding(fingerprint):
                self._findings.append(
                    Finding(
                        id=str(uuid4()),
                        source="endpoint",
                        finding_type="mass_encryption_detected",
                        severity="CRITICAL",
                        confidence=0.87,
                        risk_score=92,
                        status="open",
                        created_at=datetime.now(timezone.utc).isoformat(),
                        details={
                            "path": event_payload.get("path"),
                            "files_modified_per_second": modified_per_second,
                            "entropy_avg_modified_files": entropy_avg,
                            "entropy_delta": entropy_delta,
                            "thresholds": {
                                "files_modified_per_second": self._mass_file_write_threshold,
                                "entropy_avg_modified_files": self._mass_entropy_threshold,
                                "entropy_delta": self._mass_entropy_delta_threshold,
                            },
                        },
                    )
                )

        if bool(endpoint_features.get("honeypot_touched", False)):
            path = str(event_payload.get("path", "unknown"))
            fingerprint = f"endpoint:honeypot:{path}"
            if self._should_emit_finding(fingerprint):
                self._findings.append(
                    Finding(
                        id=str(uuid4()),
                        source="endpoint",
                        finding_type="honeypot_touched",
                        severity="CRITICAL",
                        confidence=0.98,
                        risk_score=99,
                        status="open",
                        created_at=datetime.now(timezone.utc).isoformat(),
                        details={"event": dict(event_payload)},
                    )
                )

    def _refresh_correlation_and_risk_locked(self) -> None:
        correlation_flags = extract_correlation_features(
            endpoint_features=self._latest_endpoint_features,
            network_features=self._latest_network_features,
            multiple_hosts_affected=int(self._latest_network_features.get("hosts_with_smb_open", 0)) > 1,
        )

        merged_flags: dict[str, Any] = {
            **correlation_flags,
            "smb_v1_enabled": bool(self._latest_network_features.get("smb_v1_enabled", False)),
            "vss_delete_attempt": bool(self._latest_endpoint_features.get("vss_delete_attempt", False)),
            "default_credentials_found": int(self._latest_network_features.get("default_credentials_found", 0)) > 0,
            "rdp_exposed_public": bool(self._latest_network_features.get("rdp_exposed_public", False)),
        }

        correlation_alerts = self.correlation_engine.evaluate(merged_flags)
        self._correlation_alerts = correlation_alerts

        for alert in correlation_alerts:
            matched_key = "|".join(alert.matched_conditions)
            fingerprint = f"correlation:{alert.id}:{matched_key}"
            if not self._should_emit_finding(fingerprint):
                continue
            self._findings.append(
                Finding(
                    id=str(uuid4()),
                    source="correlation",
                    finding_type=alert.id.lower(),
                    severity=alert.severity,
                    confidence=alert.confidence,
                    risk_score=98 if alert.severity == "CRITICAL" else 80,
                    status="open",
                    created_at=datetime.now(timezone.utc).isoformat(),
                    details={"action": alert.action, "matched_conditions": list(alert.matched_conditions)},
                )
            )

        breakdown: RiskScoreBreakdown = self.risk_scorer.score(
            endpoint_score=self._latest_endpoint_score_0_100,
            network_score=self._latest_network_score_0_100,
            alerts=correlation_alerts,
        )

        final_score = self.inference.unified_risk_score(
            endpoint_score=breakdown.endpoint_score,
            network_score=breakdown.network_score,
            correlation_flags=correlation_flags,
        )

        self._risk_state = RiskState(
            score=final_score,
            endpoint_score=round(breakdown.endpoint_score, 2),
            network_score=round(breakdown.network_score, 2),
            correlation_bonus=round(breakdown.correlation_bonus, 2),
            updated_at=datetime.now(timezone.utc).isoformat(),
        )

    def _is_public_ip(self, target: str) -> bool:
        try:
            ip_value = ipaddress.ip_address(target)
        except ValueError:
            return False

        return not (
            ip_value.is_private
            or ip_value.is_loopback
            or ip_value.is_link_local
            or ip_value.is_multicast
            or ip_value.is_reserved
        )

    def _publish_event(self, payload: dict[str, Any]) -> None:
        if self._event_callback is None:
            return

        try:
            self._event_callback(payload)
        except Exception:
            return

    def _should_emit_finding(self, fingerprint: str) -> bool:
        now = time.monotonic()
        last_seen = self._finding_last_seen_monotonic.get(fingerprint)
        if last_seen is not None and (now - last_seen) < self._dedup_window_seconds:
            return False

        self._finding_last_seen_monotonic[fingerprint] = now

        if len(self._finding_last_seen_monotonic) > 4096:
            cutoff = now - (self._dedup_window_seconds * 2.0)
            stale_keys = [
                key
                for key, seen_at in self._finding_last_seen_monotonic.items()
                if seen_at < cutoff
            ]
            for key in stale_keys:
                self._finding_last_seen_monotonic.pop(key, None)

        return True

    def _risk_status_text(self, score: int) -> str:
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        return "LOW"

    def _risk_summary_text(self, *, status: str, score: int) -> str:
        if status == "CRITICAL":
            return f"Riesgo muy alto ({score}/100). Se recomienda aislamiento y respuesta inmediata."
        if status == "HIGH":
            return f"Riesgo alto ({score}/100). Hay señales que requieren atencion hoy."
        if status == "MEDIUM":
            return f"Riesgo moderado ({score}/100). Conviene revisar y reforzar configuraciones."
        return f"Riesgo bajo ({score}/100). No hay evidencia fuerte de actividad de ransomware."

    def _build_top_reasons(
        self,
        endpoint_features: Mapping[str, float | int | bool],
        network_features: Mapping[str, float | int | bool],
        correlation_flags: Mapping[str, bool],
    ) -> list[str]:
        reasons: list[str] = []

        if bool(endpoint_features.get("honeypot_touched", False)):
            reasons.append("Se toco un archivo trampa, lo cual es una senal fuerte de actividad maliciosa.")
        if float(endpoint_features.get("files_modified_per_second", 0.0)) >= self._mass_file_write_threshold:
            reasons.append("Se detecto modificacion masiva de archivos en pocos segundos.")
        if float(endpoint_features.get("entropy_avg_modified_files", 0.0)) >= self._mass_entropy_threshold:
            reasons.append("Los archivos cambiados se parecen a contenido cifrado.")
        if bool(endpoint_features.get("vss_delete_attempt", False)):
            reasons.append("Hubo intento de borrar copias de respaldo.")
        if bool(network_features.get("smb_v1_enabled", False)):
            reasons.append("SMBv1 activo: protocolo antiguo usado en ataques de propagacion.")
        if bool(network_features.get("rdp_exposed_public", False)):
            reasons.append("RDP expuesto a internet, aumenta riesgo de acceso no autorizado.")
        if int(network_features.get("services_with_weak_credentials", 0)) > 0:
            reasons.append("Se encontraron servicios con credenciales debiles.")
        if bool(correlation_flags.get("smb_open_AND_mass_file_write", False)):
            reasons.append("Coincidencia de red y endpoint: SMB abierto junto con escritura masiva.")

        return reasons[:6]

    def _explain_alert(self, alert: Mapping[str, Any]) -> dict[str, Any]:
        alert_id = str(alert.get("id", "UNKNOWN"))
        descriptions = {
            "WANNA_CRY_PATTERN": "Patron parecido a WannaCry: cifrado masivo + movimiento por SMB + intento de borrar respaldos.",
            "RDP_INTRUSION": "Posible intrusion por RDP con credenciales debiles y proceso nuevo sospechoso.",
            "LATERAL_MOVEMENT": "Posible propagacion lateral entre varios equipos.",
        }

        condition_labels = {
            "smb_v1_enabled": "SMBv1 habilitado",
            "mass_file_encryption": "Se detecta comportamiento de cifrado",
            "vss_delete_attempt": "Intento de borrar respaldos",
            "rdp_exposed_public": "RDP expuesto a internet",
            "default_credentials_found": "Credenciales por defecto encontradas",
            "new_unknown_process": "Proceso nuevo y no confiable",
            "smb_open_AND_mass_file_write": "SMB abierto junto con escritura masiva",
            "multiple_hosts_affected": "Mas de un host afectado",
        }

        matched = [condition_labels.get(item, item) for item in alert.get("matched_conditions", [])]

        return {
            "id": alert_id,
            "severity": str(alert.get("severity", "UNKNOWN")),
            "confidence": float(alert.get("confidence", 0.0)),
            "action": str(alert.get("action", "ALERT")),
            "description": descriptions.get(alert_id, "Se detecto una correlacion de riesgo."),
            "matched_conditions_readable": matched,
        }

    def _build_suggested_actions(
        self,
        status: str,
        endpoint_features: Mapping[str, float | int | bool],
        network_features: Mapping[str, float | int | bool],
        alerts: list[dict[str, Any]],
    ) -> list[str]:
        actions: list[str] = []

        if status in {"HIGH", "CRITICAL"}:
            actions.append("Aislar temporalmente el equipo afectado de la red.")
        if bool(endpoint_features.get("honeypot_touched", False)) or bool(endpoint_features.get("vss_delete_attempt", False)):
            actions.append("Revisar procesos activos y detener el proceso sospechoso mas reciente.")
        if bool(network_features.get("smb_v1_enabled", False)):
            actions.append("Desactivar SMBv1 y validar de nuevo el puerto 445.")
        if int(network_features.get("services_with_weak_credentials", 0)) > 0:
            actions.append("Cambiar credenciales debiles por claves fuertes y unicas.")
        if any(alert.get("id") == "RDP_INTRUSION" for alert in alerts):
            actions.append("Cerrar o restringir RDP a VPN/listas permitidas.")

        if not actions:
            actions.append("Mantener monitoreo activo y ejecutar escaneos periodicos.")

        return actions[:6]
