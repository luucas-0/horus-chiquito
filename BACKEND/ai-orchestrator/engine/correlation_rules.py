"""Correlation rules that merge network and endpoint signals."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class CorrelationRule:
    """One correlation rule combining multiple conditions."""

    id: str
    conditions: tuple[str, ...]
    severity: str
    confidence: float
    action: str


@dataclass(frozen=True)
class CorrelationAlert:
    """Triggered correlation alert for the unified dashboard/API."""

    id: str
    severity: str
    confidence: float
    action: str
    matched_conditions: tuple[str, ...]


DEFAULT_CORRELATION_RULES: tuple[CorrelationRule, ...] = (
    CorrelationRule(
        id="WANNA_CRY_PATTERN",
        conditions=("smb_v1_enabled", "mass_file_encryption", "vss_delete_attempt"),
        severity="CRITICAL",
        confidence=0.95,
        action="ISOLATE_HOST_IMMEDIATELY",
    ),
    CorrelationRule(
        id="RDP_INTRUSION",
        conditions=("rdp_exposed_public", "default_credentials_found", "new_unknown_process"),
        severity="CRITICAL",
        confidence=0.90,
        action="BLOCK_RDP_AND_ALERT",
    ),
    CorrelationRule(
        id="LATERAL_MOVEMENT",
        conditions=("smb_open_AND_mass_file_write", "multiple_hosts_affected"),
        severity="HIGH",
        confidence=0.85,
        action="SEGMENT_NETWORK",
    ),
)


class CorrelationEngine:
    """Evaluate correlation rules against merged feature flags."""

    def __init__(self, rules: Iterable[CorrelationRule] | None = None) -> None:
        self.rules: tuple[CorrelationRule, ...] = tuple(rules or DEFAULT_CORRELATION_RULES)

    @classmethod
    def from_json_file(cls, path: str | Path | None) -> "CorrelationEngine":
        """Load correlation rules from JSON with safe fallback."""

        if not path:
            return cls()

        file_path = Path(path)
        if not file_path.exists():
            return cls()

        try:
            payload = json.loads(file_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls()

        rules: list[CorrelationRule] = []
        for entry in payload if isinstance(payload, list) else []:
            try:
                rules.append(
                    CorrelationRule(
                        id=str(entry["id"]),
                        conditions=tuple(str(item) for item in entry["conditions"]),
                        severity=str(entry["severity"]).upper(),
                        confidence=float(entry.get("confidence", 0.5)),
                        action=str(entry.get("action", "ALERT")),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue

        return cls(rules=rules or None)

    def evaluate(self, flags: Mapping[str, Any]) -> list[CorrelationAlert]:
        """Return all alerts whose conditions are all satisfied."""

        alerts: list[CorrelationAlert] = []
        for rule in self.rules:
            matched_conditions: list[str] = []
            is_match = True
            for condition in rule.conditions:
                value = flags.get(condition, False)
                if not bool(value):
                    is_match = False
                    break
                matched_conditions.append(condition)

            if not is_match:
                continue

            alerts.append(
                CorrelationAlert(
                    id=rule.id,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    action=rule.action,
                    matched_conditions=tuple(matched_conditions),
                )
            )

        return alerts
