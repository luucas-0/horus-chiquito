"""Process telemetry collector for suspicious endpoint behavior."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import shlex
import subprocess
from typing import Any


@dataclass(frozen=True)
class ProcessSnapshot:
    """Observed process metadata used for endpoint features."""

    pid: int
    command: str
    process_age_seconds: float
    process_is_signed: bool
    process_has_network_access: bool
    process_spawned_by_suspicious: bool


class ProcessMonitor:
    """Collect lightweight process metadata from local system."""

    def snapshot(self, pid: int | None = None) -> ProcessSnapshot:
        """Return snapshot for one PID or generic fallback snapshot."""

        if pid is None:
            return ProcessSnapshot(
                pid=-1,
                command="unknown",
                process_age_seconds=60.0,
                process_is_signed=False,
                process_has_network_access=False,
                process_spawned_by_suspicious=False,
            )

        command = self._read_process_command(pid)
        is_signed = self._is_likely_signed_binary(command)

        return ProcessSnapshot(
            pid=pid,
            command=command,
            process_age_seconds=60.0,
            process_is_signed=is_signed,
            process_has_network_access=self._looks_network_capable(command),
            process_spawned_by_suspicious=False,
        )

    def _read_process_command(self, pid: int) -> str:
        try:
            result = subprocess.run(
                ["ps", "-p", str(pid), "-o", "command="],
                check=False,
                text=True,
                capture_output=True,
                timeout=2,
            )
        except Exception:
            return "unknown"

        command = (result.stdout or "").strip()
        return command or "unknown"

    def _is_likely_signed_binary(self, command: str) -> bool:
        lowered = command.lower()
        if not lowered or lowered == "unknown":
            return False
        trusted_paths = ("/system/", "/usr/bin/", "/bin/", "applications/")
        return any(path in lowered for path in trusted_paths)

    def _looks_network_capable(self, command: str) -> bool:
        lowered = command.lower()
        return any(token in lowered for token in ("curl", "wget", "python", "node", "ssh", "nc", "nmap"))
