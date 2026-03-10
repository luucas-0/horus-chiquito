"""Real-time inference with model-backed and heuristic fallback modes."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import os
from pathlib import Path
import time
from typing import Any, Mapping


@dataclass
class InferenceDiagnostics:
    """Runtime diagnostics for inference mode and latency."""

    endpoint_model_loaded: bool
    network_model_loaded: bool
    unified_model_loaded: bool
    fallback_mode: bool


class RealTimeInference:
    """Inference wrapper designed to keep scoring under configured timeout."""

    def __init__(self, model_path: str | None = None, timeout_ms: int | None = None) -> None:
        default_model_path = Path(__file__).resolve().parent / "models"
        configured_model_path = model_path or os.getenv("ML_MODEL_PATH")
        self.model_path = Path(configured_model_path) if configured_model_path else default_model_path
        self.timeout_ms = timeout_ms or int(os.getenv("ML_INFERENCE_TIMEOUT_MS", "100"))
        self.event_buffer: deque[dict[str, Any]] = deque(maxlen=500)

        self._onnxruntime = None
        self._xgboost = None
        self._endpoint_session = None
        self._network_session = None
        self._risk_model = None

        self._load_models()

    def diagnostics(self) -> InferenceDiagnostics:
        """Return runtime diagnostics used by operations and tests."""

        return InferenceDiagnostics(
            endpoint_model_loaded=self._endpoint_session is not None,
            network_model_loaded=self._network_session is not None,
            unified_model_loaded=self._risk_model is not None,
            fallback_mode=(
                self._endpoint_session is None
                or self._network_session is None
                or self._risk_model is None
            ),
        )

    def score_endpoint_event(self, event_features: Mapping[str, float | int | bool]) -> float:
        """Return endpoint ransomware probability in range [0.0, 1.0]."""

        self.event_buffer.append(dict(event_features))
        started_at = time.perf_counter()

        if self._endpoint_session is not None:
            vector = self._vectorize_endpoint(event_features)
            output = self._endpoint_session.run(None, {"input": vector})
            score = float(output[0][0])
        else:
            score = self._heuristic_endpoint_score(event_features)

        self._enforce_latency_budget(started_at)
        return max(0.0, min(score, 1.0))

    def score_network_features(self, network_features: Mapping[str, float | int | bool]) -> float:
        """Return network risk score in range [0, 100]."""

        started_at = time.perf_counter()

        if self._network_session is not None:
            vector = self._vectorize_network(network_features)
            output = self._network_session.run(None, {"input": vector})
            score = float(output[0][0]) * 100.0
        else:
            score = self._heuristic_network_score(network_features)

        self._enforce_latency_budget(started_at)
        return max(0.0, min(score, 100.0))

    def unified_risk_score(
        self,
        endpoint_score: float,
        network_score: float,
        correlation_flags: Mapping[str, bool],
    ) -> int:
        """Return final risk score in range [0, 100]."""

        started_at = time.perf_counter()

        if self._risk_model is not None and self._xgboost is not None:
            features = [
                max(0.0, min(endpoint_score, 100.0)),
                max(0.0, min(network_score, 100.0)),
                *[1.0 if bool(value) else 0.0 for value in correlation_flags.values()],
            ]
            dmatrix = self._xgboost.DMatrix([features])
            score = float(self._risk_model.predict(dmatrix)[0])
        else:
            score = (endpoint_score * 0.45) + (network_score * 0.45) + (10.0 * sum(1 for value in correlation_flags.values() if value))

        self._enforce_latency_budget(started_at)
        return int(round(max(0.0, min(score, 100.0))))

    def _load_models(self) -> None:
        """Try loading ONNX/XGBoost models; fallback if unavailable."""

        try:
            import onnxruntime  # type: ignore

            self._onnxruntime = onnxruntime
        except Exception:
            self._onnxruntime = None

        try:
            import xgboost  # type: ignore

            self._xgboost = xgboost
        except Exception:
            self._xgboost = None

        if self._onnxruntime is not None:
            endpoint_model = self.model_path / "ransomware_behavior.onnx"
            network_model = self.model_path / "network_anomaly.onnx"
            if endpoint_model.exists():
                self._endpoint_session = self._onnxruntime.InferenceSession(str(endpoint_model))
            if network_model.exists():
                self._network_session = self._onnxruntime.InferenceSession(str(network_model))

        if self._xgboost is not None:
            risk_model_json = self.model_path / "unified_risk_scorer.json"
            risk_model_bin = self.model_path / "unified_risk_scorer.pkl"

            if risk_model_json.exists():
                booster = self._xgboost.Booster()
                booster.load_model(str(risk_model_json))
                self._risk_model = booster
            elif risk_model_bin.exists():
                booster = self._xgboost.Booster()
                booster.load_model(str(risk_model_bin))
                self._risk_model = booster

    def _heuristic_endpoint_score(self, features: Mapping[str, float | int | bool]) -> float:
        score = 0.0
        score += min(float(features.get("files_modified_per_second", 0.0)) / 100.0, 0.25)
        score += min(float(features.get("files_renamed_per_second", 0.0)) / 40.0, 0.20)
        score += min(float(features.get("entropy_avg_modified_files", 0.0)) / 8.0, 0.25)
        score += 0.30 if bool(features.get("honeypot_touched", False)) else 0.0
        score += 0.25 if bool(features.get("vss_delete_attempt", False)) else 0.0
        score += 0.10 if not bool(features.get("process_is_signed", True)) else 0.0
        return max(0.0, min(score, 1.0))

    def _heuristic_network_score(self, features: Mapping[str, float | int | bool]) -> float:
        score = 0.0
        score += min(int(features.get("open_critical_ports_count", 0)) * 12.0, 36.0)
        score += min(int(features.get("services_with_weak_credentials", 0)) * 18.0, 36.0)
        score += min(int(features.get("outdated_service_versions", 0)) * 4.0, 16.0)
        score += min(int(features.get("critical_cves_detected", 0)) * 6.0, 24.0)
        score += 12.0 if bool(features.get("rdp_exposed_public", False)) else 0.0
        score += 15.0 if bool(features.get("smb_v1_enabled", False)) else 0.0
        score += float(features.get("lateral_movement_risk", 0.0)) * 25.0
        return max(0.0, min(score, 100.0))

    def _vectorize_endpoint(self, features: Mapping[str, float | int | bool]) -> list[list[float]]:
        ordered = [
            float(features.get("files_modified_per_second", 0.0)),
            float(features.get("files_renamed_per_second", 0.0)),
            float(features.get("files_deleted_per_second", 0.0)),
            float(features.get("unique_extensions_changed", 0.0)),
            float(features.get("entropy_avg_modified_files", 0.0)),
            float(features.get("entropy_delta", 0.0)),
            1.0 if bool(features.get("process_is_signed", False)) else 0.0,
            1.0 if bool(features.get("process_has_network_access", False)) else 0.0,
            1.0 if bool(features.get("process_spawned_by_suspicious", False)) else 0.0,
            float(features.get("process_age_seconds", 0.0)),
            float(features.get("api_crypto_calls_per_second", 0.0)),
            1.0 if bool(features.get("honeypot_touched", False)) else 0.0,
            1.0 if bool(features.get("honeypot_modified", False)) else 0.0,
            1.0 if bool(features.get("vss_delete_attempt", False)) else 0.0,
            1.0 if bool(features.get("backup_path_access", False)) else 0.0,
        ]
        return [ordered]

    def _vectorize_network(self, features: Mapping[str, float | int | bool]) -> list[list[float]]:
        ordered = [
            float(features.get("open_critical_ports_count", 0.0)),
            float(features.get("services_with_weak_credentials", 0.0)),
            float(features.get("unencrypted_services_count", 0.0)),
            1.0 if bool(features.get("smb_v1_enabled", False)) else 0.0,
            1.0 if bool(features.get("rdp_exposed_public", False)) else 0.0,
            float(features.get("outdated_service_versions", 0.0)),
            float(features.get("critical_cves_detected", 0.0)),
            float(features.get("default_credentials_found", 0.0)),
            float(features.get("empty_password_services", 0.0)),
            float(features.get("hosts_with_smb_open", 0.0)),
            float(features.get("lateral_movement_risk", 0.0)),
        ]
        return [ordered]

    def _enforce_latency_budget(self, started_at: float) -> None:
        elapsed_ms = (time.perf_counter() - started_at) * 1000.0
        if elapsed_ms <= self.timeout_ms:
            return
