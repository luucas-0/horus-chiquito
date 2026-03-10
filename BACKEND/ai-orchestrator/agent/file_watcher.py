"""Filesystem watcher with polling fallback for endpoint telemetry."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
import threading
import time
from typing import Any, Callable

from agent.entropy_analyzer import EntropyAnalyzer
from agent.honeypot_manager import HoneypotManager
from agent.process_monitor import ProcessMonitor


@dataclass(frozen=True)
class FileEvent:
    """Normalized file event emitted by watcher."""

    timestamp: str
    action: str
    path: str
    extension_after: str | None
    entropy_before: float
    entropy_after: float
    process_pid: int | None
    process_is_signed: bool
    process_has_network_access: bool
    process_spawned_by_suspicious: bool
    process_age_seconds: float
    api_crypto_calls: float
    honeypot_touched: bool
    honeypot_modified: bool
    vss_delete_attempt: bool
    backup_path_access: bool


class FileWatcher:
    """Directory polling watcher that emits normalized endpoint events."""

    def __init__(self, directories: list[str], on_event: Callable[[dict[str, Any]], None]) -> None:
        self.directories = [Path(directory).expanduser().resolve() for directory in directories]
        self.on_event = on_event
        self.honeypots = HoneypotManager(directories)
        self.entropy = EntropyAnalyzer()
        self.process_monitor = ProcessMonitor()

        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._state: dict[str, float] = {}
        self._entropy_state: dict[str, float] = {}

    def start(self, interval_seconds: float = 1.0) -> None:
        """Start watcher loop in daemon thread."""

        self.honeypots.ensure_honeypots()
        self._capture_initial_state()

        self._thread = threading.Thread(target=self._loop, args=(interval_seconds,), daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop watcher loop."""

        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _loop(self, interval_seconds: float) -> None:
        while not self._stop.is_set():
            self._scan_once()
            time.sleep(interval_seconds)

    def _capture_initial_state(self) -> None:
        for directory in self.directories:
            directory.mkdir(parents=True, exist_ok=True)
            for file_path in directory.rglob("*"):
                if file_path.is_file():
                    self._state[str(file_path)] = file_path.stat().st_mtime
                    try:
                        self._entropy_state[str(file_path)] = self.entropy.shannon_entropy(file_path.read_bytes())
                    except Exception:
                        self._entropy_state[str(file_path)] = 0.0

    def _scan_once(self) -> None:
        current_state: dict[str, float] = {}

        for directory in self.directories:
            for file_path in directory.rglob("*"):
                if not file_path.is_file():
                    continue
                current_state[str(file_path)] = file_path.stat().st_mtime

        previous_paths = set(self._state)
        current_paths = set(current_state)

        created = current_paths - previous_paths
        deleted = previous_paths - current_paths
        maybe_modified = {path for path in current_paths & previous_paths if current_state[path] != self._state[path]}

        for path in created:
            self._emit_event("created", Path(path))

        for path in deleted:
            self._emit_event("deleted", Path(path))

        for path in maybe_modified:
            self._emit_event("modified", Path(path))

        self._state = current_state

    def _emit_event(self, action: str, path: Path) -> None:
        path_key = str(path)
        before_entropy = float(self._entropy_state.get(path_key, 0.0))
        after_entropy = before_entropy

        if path.exists() and path.is_file():
            try:
                content = path.read_bytes()
                after_entropy = self.entropy.shannon_entropy(content)
            except Exception:
                after_entropy = before_entropy

        if action == "deleted":
            self._entropy_state.pop(path_key, None)
            after_entropy = 0.0
        else:
            self._entropy_state[path_key] = after_entropy

        process = self.process_monitor.snapshot(None)
        honeypot_touched = self.honeypots.is_honeypot_path(str(path))

        payload = FileEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            action=action,
            path=str(path),
            extension_after=path.suffix.lower() if path.suffix else None,
            entropy_before=before_entropy,
            entropy_after=after_entropy,
            process_pid=None,
            process_is_signed=process.process_is_signed,
            process_has_network_access=process.process_has_network_access,
            process_spawned_by_suspicious=process.process_spawned_by_suspicious,
            process_age_seconds=process.process_age_seconds,
            api_crypto_calls=0.0,
            honeypot_touched=honeypot_touched,
            honeypot_modified=honeypot_touched and action == "modified",
            vss_delete_attempt=False,
            backup_path_access="backup" in str(path).lower() or "time machine" in str(path).lower(),
        )

        self.on_event(asdict(payload))
