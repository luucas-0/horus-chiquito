from __future__ import annotations

import time

from engine.ml.inference import RealTimeInference


def test_inference_under_latency_budget() -> None:
    inference = RealTimeInference(timeout_ms=100)

    endpoint_features = {
        "files_modified_per_second": 60.0,
        "files_renamed_per_second": 30.0,
        "files_deleted_per_second": 10.0,
        "unique_extensions_changed": 8,
        "entropy_avg_modified_files": 7.8,
        "entropy_delta": 2.1,
        "process_is_signed": False,
        "process_has_network_access": True,
        "process_spawned_by_suspicious": True,
        "process_age_seconds": 22.0,
        "api_crypto_calls_per_second": 145.0,
        "honeypot_touched": True,
        "honeypot_modified": True,
        "vss_delete_attempt": True,
        "backup_path_access": False,
    }

    network_features = {
        "open_critical_ports_count": 3,
        "services_with_weak_credentials": 2,
        "unencrypted_services_count": 1,
        "smb_v1_enabled": True,
        "rdp_exposed_public": True,
        "outdated_service_versions": 4,
        "critical_cves_detected": 2,
        "default_credentials_found": 1,
        "empty_password_services": 0,
        "hosts_with_smb_open": 3,
        "lateral_movement_risk": 0.9,
    }

    start = time.perf_counter()
    for _ in range(200):
        endpoint = inference.score_endpoint_event(endpoint_features)
        network = inference.score_network_features(network_features)
        unified = inference.unified_risk_score(endpoint * 100.0, network, {"mass_file_encryption": True})
        assert 0.0 <= endpoint <= 1.0
        assert 0.0 <= network <= 100.0
        assert 0 <= unified <= 100

    elapsed_ms_per_iteration = ((time.perf_counter() - start) * 1000.0) / 200.0
    assert elapsed_ms_per_iteration < 100.0
