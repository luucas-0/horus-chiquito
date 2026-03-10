from engine.correlation_rules import CorrelationEngine
from engine.ml.feature_extractor import extract_correlation_features


def test_correlation_detects_wannacry_pattern() -> None:
    engine = CorrelationEngine()

    flags = {
        "smb_v1_enabled": True,
        "mass_file_encryption": True,
        "vss_delete_attempt": True,
    }

    alerts = engine.evaluate(flags)
    ids = {alert.id for alert in alerts}
    assert "WANNA_CRY_PATTERN" in ids


def test_new_unknown_process_requires_endpoint_activity() -> None:
    flags = extract_correlation_features(
        endpoint_features={
            "process_is_signed": False,
            "process_age_seconds": 30.0,
            "files_modified_per_second": 0.0,
            "files_renamed_per_second": 0.0,
            "files_deleted_per_second": 0.0,
            "api_crypto_calls_per_second": 0.0,
            "honeypot_touched": False,
            "honeypot_modified": False,
            "vss_delete_attempt": False,
        },
        network_features={},
        multiple_hosts_affected=False,
    )

    assert flags["new_unknown_process"] is False


def test_new_unknown_process_triggers_with_real_activity() -> None:
    flags = extract_correlation_features(
        endpoint_features={
            "process_is_signed": False,
            "process_age_seconds": 30.0,
            "files_modified_per_second": 4.0,
            "files_renamed_per_second": 0.0,
            "files_deleted_per_second": 0.0,
            "api_crypto_calls_per_second": 0.0,
            "honeypot_touched": False,
            "honeypot_modified": False,
            "vss_delete_attempt": False,
        },
        network_features={},
        multiple_hosts_affected=False,
    )

    assert flags["new_unknown_process"] is True
