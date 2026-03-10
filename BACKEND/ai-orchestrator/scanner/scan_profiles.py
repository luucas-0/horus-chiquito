"""Scan profile definitions for network and credential checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ProfileName = Literal["fast", "balanced", "full"]


@dataclass(frozen=True)
class ScanProfile:
    """Runtime scan profile used by DockerScanner."""

    name: ProfileName
    top_ports: int
    nmap_max_retries: int
    nmap_host_timeout_sec: int
    nmap_timeout_sec: int
    enable_os_detection: bool
    enable_traceroute: bool
    hydra_max_attempts: int
    hydra_max_duration_sec: int
    hydra_max_services_per_scan: int


PROFILES: dict[ProfileName, ScanProfile] = {
    "fast": ScanProfile(
        name="fast",
        top_ports=200,
        nmap_max_retries=1,
        nmap_host_timeout_sec=18,
        nmap_timeout_sec=180,
        enable_os_detection=False,
        enable_traceroute=False,
        hydra_max_attempts=12,
        hydra_max_duration_sec=20,
        hydra_max_services_per_scan=2,
    ),
    "balanced": ScanProfile(
        name="balanced",
        top_ports=500,
        nmap_max_retries=1,
        nmap_host_timeout_sec=30,
        nmap_timeout_sec=300,
        enable_os_detection=False,
        enable_traceroute=False,
        hydra_max_attempts=24,
        hydra_max_duration_sec=35,
        hydra_max_services_per_scan=3,
    ),
    "full": ScanProfile(
        name="full",
        top_ports=1000,
        nmap_max_retries=2,
        nmap_host_timeout_sec=45,
        nmap_timeout_sec=600,
        enable_os_detection=True,
        enable_traceroute=True,
        hydra_max_attempts=60,
        hydra_max_duration_sec=90,
        hydra_max_services_per_scan=6,
    ),
}


def get_scan_profile(name: str | None) -> ScanProfile:
    """Return a safe scan profile, defaulting to fast."""

    if not name:
        return PROFILES["fast"]

    normalized = name.lower().strip()
    if normalized not in PROFILES:
        return PROFILES["fast"]

    return PROFILES[normalized]  # type: ignore[index]
