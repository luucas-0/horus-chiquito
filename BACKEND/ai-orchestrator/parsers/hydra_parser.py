"""Hydra output parser for weak credential findings."""

from __future__ import annotations

from dataclasses import dataclass, field
import re


@dataclass(frozen=True)
class HydraCredential:
    """A parsed credential discovered by Hydra."""

    username: str
    password: str


@dataclass(frozen=True)
class HydraServiceResult:
    """Parsed result for one Hydra service execution."""

    service: str
    port: int
    status: str
    credentials: list[HydraCredential] = field(default_factory=list)
    output_summary: str = ""


class HydraParser:
    """Parser for Hydra stdout/stderr textual output."""

    _credential_pattern = re.compile(r"login:\s*(\S+)\s+password:\s*(\S+)", re.IGNORECASE)

    @classmethod
    def parse(cls, raw_output: str, service: str, port: int) -> HydraServiceResult:
        """Parse Hydra text output.

        Args:
            raw_output: Full stdout/stderr captured from hydra command.
            service: Service scanned (ssh, ftp, ...).
            port: Numeric port associated with service.

        Returns:
            ``HydraServiceResult`` with normalized status and credentials.
        """

        output = raw_output or ""
        matches = cls._credential_pattern.findall(output)
        credentials = [HydraCredential(username=user, password=password) for user, password in matches]

        lowered = output.lower()
        if credentials:
            status = "credentials_found"
        elif "too many" in lowered and ("requests" in lowered or "fail" in lowered):
            status = "rate_limited"
        elif "locked" in lowered:
            status = "lockout_detected"
        elif "timeout" in lowered:
            status = "max_duration_reached"
        elif "error" in lowered:
            status = "hydra_error"
        else:
            status = "no_valid_credentials"

        summary = cls._summarize(output)

        return HydraServiceResult(
            service=service,
            port=port,
            status=status,
            credentials=credentials,
            output_summary=summary,
        )

    @staticmethod
    def _summarize(raw_output: str, max_len: int = 400) -> str:
        """Create short summary for dashboards and API payloads."""

        if not raw_output:
            return ""

        kept_lines = [
            line.strip()
            for line in raw_output.splitlines()
            if line.strip() and re.search(r"login:|password:|error|locked|limit|success|warning", line, re.IGNORECASE)
        ]
        summary = "\n".join(kept_lines)
        return summary[:max_len]
