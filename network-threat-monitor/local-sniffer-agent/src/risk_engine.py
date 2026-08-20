"""
risk_engine.py

Explainable multi-signal risk engine.

Signals:

    ML anomaly score
    Flow traffic intensity
    Device traffic intensity
    Destination diversity
    Connection pressure

The final score is 0-100.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass
class RiskResult:
    risk_score: float
    severity: str
    suggested_action: str
    reasons: List[str]


class RiskEngine:

    def __init__(
        self,
        ml_weight: float = 0.50,
        traffic_weight: float = 0.20,
        destination_weight: float = 0.15,
        flow_weight: float = 0.15,
    ):
        total = (
            ml_weight
            + traffic_weight
            + destination_weight
            + flow_weight
        )

        if total <= 0:
            raise ValueError(
                "Risk weights must sum to a positive value."
            )

        self.ml_weight = ml_weight / total
        self.traffic_weight = traffic_weight / total
        self.destination_weight = destination_weight / total
        self.flow_weight = flow_weight / total

    @staticmethod
    def clamp(
        value: float,
        minimum: float = 0.0,
        maximum: float = 100.0,
    ) -> float:
        return max(
            minimum,
            min(
                maximum,
                value,
            ),
        )

    # ------------------------------------------------------------------
    # Traffic
    # ------------------------------------------------------------------

    @staticmethod
    def traffic_score(
        bytes_per_second: float,
    ) -> float:

        rate = max(
            0.0,
            float(bytes_per_second),
        )

        if rate <= 50_000:
            return 5.0

        if rate <= 250_000:
            return 20.0

        if rate <= 1_000_000:
            return 55.0

        if rate <= 5_000_000:
            return 80.0

        if rate <= 20_000_000:
            return 95.0

        return 100.0

    # ------------------------------------------------------------------
    # Destination diversity
    # ------------------------------------------------------------------

    @staticmethod
    def destination_score(
        unique_destinations: int,
    ) -> float:

        count = max(
            0,
            int(unique_destinations),
        )

        if count <= 3:
            return 5.0

        if count <= 8:
            return 20.0

        if count <= 15:
            return 40.0

        if count <= 30:
            return 65.0

        if count <= 60:
            return 85.0

        return 100.0

    # ------------------------------------------------------------------
    # Flow pressure
    # ------------------------------------------------------------------

    @staticmethod
    def flow_score(
        flows: int,
    ) -> float:

        count = max(
            0,
            int(flows),
        )

        if count <= 5:
            return 5.0

        if count <= 10:
            return 20.0

        if count <= 20:
            return 40.0

        if count <= 35:
            return 65.0

        if count <= 60:
            return 85.0

        return 100.0

    # ------------------------------------------------------------------
    # Policy
    # ------------------------------------------------------------------

    @staticmethod
    def decision_policy(
        risk_score: float,
    ) -> tuple[str, str]:

        if risk_score >= 90:
            return (
                "CRITICAL",
                "QUARANTINE_DEVICE",
            )

        if risk_score >= 75:
            return (
                "HIGH",
                "BLOCK",
            )

        if risk_score >= 50:
            return (
                "MEDIUM",
                "REQUIRE_STEP_UP_AUTH",
            )

        if risk_score >= 25:
            return (
                "LOW",
                "MONITOR",
            )

        return (
            "NORMAL",
            "ALLOW",
        )

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        ml_threat_score: float,
        bytes_per_second: float,
        unique_destinations: int,
        flows: int,
    ) -> RiskResult:

        ml_score = self.clamp(
            float(ml_threat_score)
        )

        traffic = self.traffic_score(
            bytes_per_second
        )

        destinations = (
            self.destination_score(
                unique_destinations
            )
        )

        flow_pressure = self.flow_score(
            flows
        )

        final_score = (
            ml_score * self.ml_weight
            + traffic * self.traffic_weight
            + destinations
            * self.destination_weight
            + flow_pressure
            * self.flow_weight
        )

        final_score = round(
            self.clamp(final_score),
            2,
        )

        reasons = []

        if ml_score >= 80:
            reasons.append(
                "ML model detected strongly abnormal behavior."
            )

        elif ml_score >= 60:
            reasons.append(
                "ML model detected suspicious behavior."
            )

        elif ml_score >= 40:
            reasons.append(
                "ML model detected mildly unusual behavior."
            )

        if traffic >= 80:
            reasons.append(
                "Extremely high network throughput detected."
            )

        elif traffic >= 55:
            reasons.append(
                "Unusually high network throughput detected."
            )

        if destinations >= 65:
            reasons.append(
                "Device is communicating with an unusually "
                "large number of destinations."
            )

        if flow_pressure >= 65:
            reasons.append(
                "Unusually high connection/flow activity detected."
            )

        if not reasons:
            reasons.append(
                "Observed behavior is within the current baseline."
            )

        severity, action = (
            self.decision_policy(
                final_score
            )
        )

        return RiskResult(
            risk_score=final_score,
            severity=severity,
            suggested_action=action,
            reasons=reasons,
        )