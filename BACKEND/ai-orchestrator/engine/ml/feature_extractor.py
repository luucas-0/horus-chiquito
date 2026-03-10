"""Feature extraction for unified network and endpoint scoring."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import math
import os
from typing import Any, Iterable, Mapping

from parsers.hydra_parser import HydraServiceResult
from parsers.nmap_parser import NmapScanResult


ENDPOINT_FEATURES: dict[str, type[Any]] = {
    "files_modified_per_second": float,
    "files_renamed_per_second": float,
    "files_deleted_per_second": float,
    "unique_extensions_changed": int,
    "entropy_avg_modified_files": float,
    "entropy_delta": float,
    "process_is_signed": bool,
    "process_has_network_access": bool,
    "process_spawned_by_suspicious": bool,
    "process_age_seconds": float,
    "api_crypto_calls_per_second": float,
    "honeypot_touched": bool,
    "honeypot_modified": bool,
    "vss_delete_attempt": bool,
    "backup_path_access": bool,
}

NETWORK_FEATURES: dict[str, type[Any]] = {
    "open_critical_ports_count": int,
    "services_with_weak_credentials": int,
    "unencrypted_services_count": int,
    "smb_v1_enabled": bool,
    "rdp_exposed_public": bool,
    "outdated_service_versions": int,
    "critical_cves_detected": int,
    "default_credentials_found": int,
    "empty_password_services": int,
    "hosts_with_smb_open": int,
    "lateral_movement_risk": float,
}

CORRELATION_FEATURES: dict[str, type[Any]] = {
    "smb_open_AND_mass_file_write": bool,
    "rdp_weak_cred_AND_new_process": bool,
    "ssh_compromised_AND_file_activity": bool,
    "telnet_open_AND_lateral_movement": bool,
    "mass_file_encryption": bool,
    "new_unknown_process": bool,
    "multiple_hosts_affected": bool,
}


UNENCRYPTED_SERVICES = {"telnet", "ftp", "http"}
CRITICAL_PORTS = {445, 3389, 21, 23}
DEFAULT_ENDPOINT_WINDOW_SECONDS = max(3, int(os.getenv("ENDPOINT_WINDOW_SECONDS", "10")))
MASS_FILE_WRITE_THRESHOLD = max(5.0, float(os.getenv("MASS_FILE_WRITE_THRESHOLD", "20")))
MASS_ENCRYPTION_ENTROPY_THRESHOLD = float(os.getenv("MASS_ENCRYPTION_ENTROPY_THRESHOLD", "7.5"))
MASS_ENCRYPTION_DELTA_THRESHOLD = float(os.getenv("MASS_ENCRYPTION_DELTA_THRESHOLD", "1.0"))


@dataclass(frozen=True)
class FeatureVector:
    """Container for feature vectors emitted by the extractor."""

    endpoint: dict[str, float | int | bool]
    network: dict[str, float | int | bool]
    correlation: dict[str, bool]


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)

    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)

    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(text).astimezone(timezone.utc)
        except ValueError:
            pass

    return datetime.now(timezone.utc)


def extract_endpoint_features(events: Iterable[Mapping[str, Any]], window_seconds: int | None = None) -> dict[str, float | int | bool]:
    """Extract endpoint telemetry features from recent agent events."""

    resolved_window = window_seconds if window_seconds is not None else DEFAULT_ENDPOINT_WINDOW_SECONDS
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=resolved_window)

    recent_events = [event for event in events if _parse_timestamp(event.get("timestamp")) >= window_start]
    if not recent_events:
        return {key: _default_for_type(value_type) for key, value_type in ENDPOINT_FEATURES.items()}

    action_counter: Counter[str] = Counter(str(event.get("action", "unknown")).lower() for event in recent_events)
    modified_events = [event for event in recent_events if str(event.get("action", "")).lower() == "modified"]

    entropy_values: list[float] = [float(event.get("entropy_after", 0.0)) for event in modified_events if event.get("entropy_after") is not None]
    entropy_deltas: list[float] = [
        float(event.get("entropy_after", 0.0)) - float(event.get("entropy_before", 0.0))
        for event in modified_events
        if event.get("entropy_after") is not None
    ]

    extension_changes = {
        str(event.get("extension_after", "")).lower()
        for event in recent_events
        if event.get("extension_after")
    }

    suspicious_parent = any(bool(event.get("process_spawned_by_suspicious", False)) for event in recent_events)
    process_signed = all(bool(event.get("process_is_signed", False)) for event in recent_events)
    process_network_access = any(bool(event.get("process_has_network_access", False)) for event in recent_events)
    honeypot_touched = any(bool(event.get("honeypot_touched", False)) for event in recent_events)
    honeypot_modified = any(bool(event.get("honeypot_modified", False)) for event in recent_events)
    vss_delete_attempt = any(bool(event.get("vss_delete_attempt", False)) for event in recent_events)
    backup_path_access = any(bool(event.get("backup_path_access", False)) for event in recent_events)

    process_ages = [float(event.get("process_age_seconds", 0.0)) for event in recent_events if event.get("process_age_seconds") is not None]
    crypto_calls = [float(event.get("api_crypto_calls", 0.0)) for event in recent_events]

    return {
        "files_modified_per_second": action_counter.get("modified", 0) / float(resolved_window),
        "files_renamed_per_second": action_counter.get("renamed", 0) / float(resolved_window),
        "files_deleted_per_second": action_counter.get("deleted", 0) / float(resolved_window),
        "unique_extensions_changed": len(extension_changes),
        "entropy_avg_modified_files": _safe_mean(entropy_values),
        "entropy_delta": _safe_mean(entropy_deltas),
        "process_is_signed": process_signed,
        "process_has_network_access": process_network_access,
        "process_spawned_by_suspicious": suspicious_parent,
        "process_age_seconds": _safe_mean(process_ages),
        "api_crypto_calls_per_second": sum(crypto_calls) / float(resolved_window),
        "honeypot_touched": honeypot_touched,
        "honeypot_modified": honeypot_modified,
        "vss_delete_attempt": vss_delete_attempt,
        "backup_path_access": backup_path_access,
    }


def extract_network_features(
    nmap_result: NmapScanResult,
    hydra_results: Iterable[HydraServiceResult],
    *,
    target_is_public: bool,
) -> dict[str, float | int | bool]:
    """Extract network telemetry features from parsed scan outputs."""

    open_ports: list[tuple[int, str | None, str | None]] = []
    hosts_with_smb_open = 0

    for host in nmap_result.hosts:
        has_smb = False
        for port in host.ports:
            if port.state != "open":
                continue
            open_ports.append((port.port, port.service, port.version))
            if port.port == 445:
                has_smb = True
        if has_smb:
            hosts_with_smb_open += 1

    weak_credentials = 0
    default_credentials = 0
    empty_password_services = 0

    for result in hydra_results:
        if result.status != "credentials_found":
            continue
        weak_credentials += 1
        for credential in result.credentials:
            pair = f"{credential.username}:{credential.password}".lower()
            if pair in {"admin:admin", "root:root", "user:user", "test:test"}:
                default_credentials += 1
            if credential.password == "":
                empty_password_services += 1

    critical_open_count = sum(1 for port, _, _ in open_ports if port in CRITICAL_PORTS)
    unencrypted_count = sum(1 for _, service, _ in open_ports if (service or "").lower() in UNENCRYPTED_SERVICES)
    outdated_versions = sum(1 for _, _, version in open_ports if _looks_outdated(version))

    smb_v1_enabled = any(
        port == 445 and "1." in (version or "")
        for port, _, version in open_ports
    )

    rdp_exposed_public = target_is_public and any(port == 3389 for port, _, _ in open_ports)

    lateral_risk_raw = (
        (0.35 if hosts_with_smb_open > 0 else 0.0)
        + min(critical_open_count * 0.1, 0.35)
        + min(unencrypted_count * 0.05, 0.20)
        + (0.10 if weak_credentials > 0 else 0.0)
    )

    return {
        "open_critical_ports_count": critical_open_count,
        "services_with_weak_credentials": weak_credentials,
        "unencrypted_services_count": unencrypted_count,
        "smb_v1_enabled": smb_v1_enabled,
        "rdp_exposed_public": rdp_exposed_public,
        "outdated_service_versions": outdated_versions,
        "critical_cves_detected": _estimate_critical_cves(outdated_versions, smb_v1_enabled),
        "default_credentials_found": default_credentials,
        "empty_password_services": empty_password_services,
        "hosts_with_smb_open": hosts_with_smb_open,
        "lateral_movement_risk": round(min(lateral_risk_raw, 1.0), 3),
    }


def extract_correlation_features(
    endpoint_features: Mapping[str, float | int | bool],
    network_features: Mapping[str, float | int | bool],
    *,
    multiple_hosts_affected: bool,
) -> dict[str, bool]:
    """Build boolean correlation flags from endpoint + network vectors."""

    endpoint_activity = (
        float(endpoint_features.get("files_modified_per_second", 0.0)) > 0.0
        or float(endpoint_features.get("files_renamed_per_second", 0.0)) > 0.0
        or float(endpoint_features.get("files_deleted_per_second", 0.0)) > 0.0
        or float(endpoint_features.get("api_crypto_calls_per_second", 0.0)) > 0.0
        or bool(endpoint_features.get("honeypot_touched", False))
        or bool(endpoint_features.get("honeypot_modified", False))
        or bool(endpoint_features.get("vss_delete_attempt", False))
    )

    mass_file_write = float(endpoint_features.get("files_modified_per_second", 0.0)) >= MASS_FILE_WRITE_THRESHOLD
    mass_encryption = (
        float(endpoint_features.get("entropy_avg_modified_files", 0.0)) >= MASS_ENCRYPTION_ENTROPY_THRESHOLD
        and float(endpoint_features.get("entropy_delta", 0.0)) >= MASS_ENCRYPTION_DELTA_THRESHOLD
    )
    new_unknown_process = (
        endpoint_activity
        and not bool(endpoint_features.get("process_is_signed", True))
        and float(endpoint_features.get("process_age_seconds", 10_000.0)) < 120.0
    )

    smb_open = bool(network_features.get("hosts_with_smb_open", 0))
    telnet_open = int(network_features.get("open_critical_ports_count", 0)) > 0 and int(network_features.get("unencrypted_services_count", 0)) > 0

    return {
        "smb_open_AND_mass_file_write": smb_open and mass_file_write,
        "rdp_weak_cred_AND_new_process": bool(network_features.get("rdp_exposed_public", False))
        and int(network_features.get("default_credentials_found", 0)) > 0
        and new_unknown_process,
        "ssh_compromised_AND_file_activity": int(network_features.get("services_with_weak_credentials", 0)) > 0
        and float(endpoint_features.get("files_modified_per_second", 0.0)) > 10.0,
        "telnet_open_AND_lateral_movement": telnet_open and float(network_features.get("lateral_movement_risk", 0.0)) >= 0.6,
        "mass_file_encryption": mass_encryption,
        "new_unknown_process": new_unknown_process,
        "multiple_hosts_affected": multiple_hosts_affected,
    }


def _estimate_critical_cves(outdated_count: int, smb_v1_enabled: bool) -> int:
    if outdated_count <= 0 and not smb_v1_enabled:
        return 0

    cve_count = outdated_count // 2
    if smb_v1_enabled:
        cve_count += 1
    return cve_count


def _looks_outdated(version: str | None) -> bool:
    if not version:
        return False

    digits = "".join(char if (char.isdigit() or char == ".") else "" for char in version)
    if not digits:
        return False

    try:
        major = int(digits.split(".")[0])
    except ValueError:
        return False

    return major <= 3


def _safe_mean(values: Iterable[float]) -> float:
    numbers = list(values)
    if not numbers:
        return 0.0
    return float(sum(numbers) / len(numbers))


def _default_for_type(type_hint: type[Any]) -> float | int | bool:
    if type_hint is bool:
        return False
    if type_hint is int:
        return 0
    if type_hint is float:
        return 0.0
    return False


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits per byte."""

    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy
