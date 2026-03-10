from __future__ import annotations

import os
import time
from collections import Counter

from engine.analysis_engine import AnalysisEngine, Finding
from engine.ml.feature_extractor import ENDPOINT_FEATURES


def test_analysis_engine_scan_job_and_findings() -> None:
    os.environ["SCANNER_MOCK_MODE"] = "true"
    engine = AnalysisEngine()

    scan_id = engine.start_network_scan("127.0.0.1", "fast")

    deadline = time.time() + 5
    status = None
    while time.time() < deadline:
        status = engine.get_scan_status(scan_id)
        if status and status["status"] in {"completed", "failed"}:
            break
        time.sleep(0.05)

    assert status is not None
    assert status["status"] == "completed"

    findings = engine.get_findings()
    assert len(findings) >= 1

    risk = engine.get_risk_score()
    assert 0 <= risk["score"] <= 100


def test_initial_risk_without_real_events_stays_zero() -> None:
    engine = AnalysisEngine()
    engine._refresh_correlation_and_risk_locked()

    risk = engine.get_risk_score()
    assert risk["score"] == 0
    assert risk["correlation_bonus"] == 0


def test_risk_explanation_without_signals() -> None:
    engine = AnalysisEngine()
    engine._refresh_correlation_and_risk_locked()

    explanation = engine.get_risk_explanation()
    assert explanation["risk"]["score"] == 0
    assert explanation["status"] == "LOW"
    assert explanation["active_flags"]["count"] == 0


def test_risk_explanation_shows_wannacry_correlation() -> None:
    engine = AnalysisEngine()

    endpoint_defaults = {
        key: False if value_type is bool else 0.0 if value_type is float else 0
        for key, value_type in ENDPOINT_FEATURES.items()
    }
    endpoint_defaults.update({
        "entropy_avg_modified_files": 7.9,
        "entropy_delta": 1.4,
        "vss_delete_attempt": True,
        "files_modified_per_second": 60.0,
    })

    engine._latest_endpoint_features = endpoint_defaults
    engine._latest_network_features = {
        "smb_v1_enabled": True,
        "hosts_with_smb_open": 1,
        "default_credentials_found": 0,
        "rdp_exposed_public": False,
    }
    engine._latest_endpoint_score_0_100 = 90.0
    engine._latest_network_score_0_100 = 70.0
    engine._refresh_correlation_and_risk_locked()

    explanation = engine.get_risk_explanation()
    ids = {item["id"] for item in explanation["correlations"]}
    assert "WANNA_CRY_PATTERN" in ids


def test_get_finding_accepts_unique_prefix() -> None:
    engine = AnalysisEngine()
    engine._findings = [
        Finding(
            id="aaaaaaaa-1111-2222-3333-444444444444",
            source="network",
            finding_type="telnet_open",
            severity="MEDIUM",
            confidence=0.6,
            risk_score=55,
            status="open",
            created_at="2026-02-19T00:00:00+00:00",
            details={},
        )
    ]

    finding = engine.get_finding("aaaaaaaa")
    assert finding is not None
    assert finding["id"] == "aaaaaaaa-1111-2222-3333-444444444444"


def test_get_finding_rejects_ambiguous_prefix() -> None:
    engine = AnalysisEngine()
    engine._findings = [
        Finding(
            id="bbbbbbbb-1111-2222-3333-444444444444",
            source="network",
            finding_type="telnet_open",
            severity="MEDIUM",
            confidence=0.6,
            risk_score=55,
            status="open",
            created_at="2026-02-19T00:00:00+00:00",
            details={},
        ),
        Finding(
            id="bbbbbbbb-9999-2222-3333-444444444444",
            source="network",
            finding_type="telnet_open",
            severity="MEDIUM",
            confidence=0.6,
            risk_score=55,
            status="open",
            created_at="2026-02-19T00:00:01+00:00",
            details={},
        ),
    ]

    assert engine.get_finding("bbbbbbbb") is None


def test_risk_score_payload_includes_feature_vectors() -> None:
    engine = AnalysisEngine()
    engine.ingest_agent_event({"action": "modified", "path": "/tmp/a.locked", "entropy_before": 1.0, "entropy_after": 7.8})

    risk = engine.get_risk_score()
    assert "endpoint_features" in risk
    assert "network_features" in risk
    assert isinstance(risk["endpoint_features"], dict)
    assert isinstance(risk["network_features"], dict)


def test_endpoint_findings_are_deduplicated_for_repeated_same_event() -> None:
    engine = AnalysisEngine()
    engine._dedup_window_seconds = 9999.0

    payload = {
        "action": "modified",
        "path": "/tmp/demo.locked",
        "entropy_before": 2.0,
        "entropy_after": 7.9,
        "honeypot_touched": True,
        "honeypot_modified": True,
        "vss_delete_attempt": True,
    }

    for _ in range(60):
        engine.ingest_agent_event(payload)

    finding_types = Counter(item["finding_type"] for item in engine.get_findings())
    assert finding_types["honeypot_touched"] == 1
    assert finding_types["mass_encryption_detected"] == 1
