"""Unified risk scoring for network + endpoint + correlation signals."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from engine.correlation_rules import CorrelationAlert


@dataclass(frozen=True)
class RiskScoreBreakdown:
    """Detailed risk score breakdown."""

    endpoint_score: float
    network_score: float
    correlation_bonus: float
    total_score: int


class UnifiedRiskScorer:
    """Combines endpoint, network and correlation signals into 0-100 score."""

    def __init__(self, endpoint_weight: float = 0.45, network_weight: float = 0.45, correlation_weight: float = 0.10) -> None:
        self.endpoint_weight = endpoint_weight
        self.network_weight = network_weight
        self.correlation_weight = correlation_weight

    def score(self, endpoint_score: float, network_score: float, alerts: Iterable[CorrelationAlert]) -> RiskScoreBreakdown:
        """Compute final bounded risk score."""

        endpoint_normalized = max(0.0, min(endpoint_score, 100.0))
        network_normalized = max(0.0, min(network_score, 100.0))

        correlation_bonus = 0.0
        for alert in alerts:
            if alert.severity == "CRITICAL":
                correlation_bonus += 30.0 * alert.confidence
            elif alert.severity == "HIGH":
                correlation_bonus += 18.0 * alert.confidence
            elif alert.severity == "MEDIUM":
                correlation_bonus += 10.0 * alert.confidence
            else:
                correlation_bonus += 4.0 * alert.confidence

        weighted = (
            (endpoint_normalized * self.endpoint_weight)
            + (network_normalized * self.network_weight)
            + (correlation_bonus * self.correlation_weight)
        )

        total_score = int(round(max(0.0, min(weighted, 100.0))))
        return RiskScoreBreakdown(
            endpoint_score=endpoint_normalized,
            network_score=network_normalized,
            correlation_bonus=round(correlation_bonus, 2),
            total_score=total_score,
        )
