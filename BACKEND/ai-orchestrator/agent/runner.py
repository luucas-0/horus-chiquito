"""Endpoint telemetry runner that streams file events to the unified API."""

from __future__ import annotations

import argparse
import json
import signal
import threading
import time
from typing import Iterable
from urllib import error, request

from agent.file_watcher import FileWatcher


DEFAULT_WATCH_DIRECTORIES = ("~/Desktop", "~/Documents", "~/Downloads")


class EndpointAgentRunner:
    """Run FileWatcher and forward events to /api/v2/agent/event."""

    def __init__(
        self,
        *,
        api_base: str,
        directories: Iterable[str],
        interval_seconds: float,
        request_timeout_seconds: float,
    ) -> None:
        self.api_base = api_base.rstrip("/")
        self.event_endpoint = f"{self.api_base}/api/v2/agent/event"
        self.interval_seconds = interval_seconds
        self.request_timeout_seconds = request_timeout_seconds
        self._stop = threading.Event()
        self._watcher = FileWatcher(directories=list(directories), on_event=self._send_event)

    def start(self) -> None:
        """Start watcher loop and keep process alive until stopped."""

        self._watcher.start(interval_seconds=self.interval_seconds)
        print(f"[agent] active -> {self.event_endpoint}")
        while not self._stop.is_set():
            time.sleep(0.5)

    def stop(self) -> None:
        """Stop watcher and flush shutdown."""

        if self._stop.is_set():
            return
        self._stop.set()
        self._watcher.stop()
        print("[agent] stopped")

    def _send_event(self, payload: dict[str, object]) -> None:
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        http_request = request.Request(
            self.event_endpoint,
            data=body,
            method="POST",
            headers={"content-type": "application/json"},
        )

        try:
            with request.urlopen(http_request, timeout=self.request_timeout_seconds) as response:
                status_code = int(getattr(response, "status", 0))
                if status_code >= 400:
                    print(f"[agent] warning: API returned HTTP {status_code}")
        except error.HTTPError as http_error:
            print(f"[agent] warning: HTTP {http_error.code} posting telemetry")
        except error.URLError as url_error:
            print(f"[agent] warning: cannot reach API ({url_error.reason})")
        except Exception as generic_error:
            print(f"[agent] warning: telemetry post failed ({generic_error})")


def _parse_directories(raw_value: str) -> list[str]:
    items = [item.strip() for item in raw_value.split(",") if item.strip()]
    return items if items else list(DEFAULT_WATCH_DIRECTORIES)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run endpoint anti-ransomware telemetry agent")
    parser.add_argument("--api-base", default="http://127.0.0.1:3000", help="Express API base URL")
    parser.add_argument(
        "--directories",
        default=",".join(DEFAULT_WATCH_DIRECTORIES),
        help="Comma-separated directories to monitor",
    )
    parser.add_argument("--interval", type=float, default=1.0, help="Watcher poll interval in seconds")
    parser.add_argument("--timeout", type=float, default=3.0, help="HTTP timeout for telemetry posts")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    directories = _parse_directories(args.directories)
    runner = EndpointAgentRunner(
        api_base=args.api_base,
        directories=directories,
        interval_seconds=max(0.2, args.interval),
        request_timeout_seconds=max(0.5, args.timeout),
    )

    def _handle_signal(_signum: int, _frame: object) -> None:
        runner.stop()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    try:
        runner.start()
    except KeyboardInterrupt:
        runner.stop()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
