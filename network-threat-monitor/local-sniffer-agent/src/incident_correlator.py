"""
incident_correlator.py

Groups repeated alerts belonging to the same security event.

Correlation key:

    device + destination + protocol + action

A repeated event within the cooldown window is treated as another
occurrence of the same incident instead of creating a new incident.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class CorrelatedIncident:
    key: str

    src_ip: str
    dst_ip: str
    protocol: str

    severity: str
    suggested_action: str

    risk_score: float

    first_seen: float
    last_seen: float

    occurrence_count: int = 1

    reasons: list[str] = field(
        default_factory=list
    )


class IncidentCorrelator:
    """
    Maintains a short-lived in-memory security event correlation table.
    """

    def __init__(
        self,
        cooldown_seconds: float = 30.0,
    ):
        self.cooldown_seconds = max(
            1.0,
            float(cooldown_seconds),
        )

        self.events: Dict[
            str,
            CorrelatedIncident,
        ] = {}

    def _make_key(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        suggested_action: str,
    ) -> str:
        return "|".join(
            [
                str(src_ip),
                str(dst_ip),
                str(protocol).upper(),
                str(suggested_action).upper(),
            ]
        )

    def _merge_reasons(
        self,
        existing: list[str],
        incoming: list[str],
    ) -> list[str]:

        merged = list(existing)

        for reason in incoming:

            if reason not in merged:
                merged.append(reason)

        return merged

    def observe(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        risk_score: float,
        severity: str,
        suggested_action: str,
        reasons: list[str],
        timestamp: Optional[float] = None,
    ) -> tuple[CorrelatedIncident, bool]:

        now = (
            timestamp
            if timestamp is not None
            else time.time()
        )

        key = self._make_key(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            suggested_action=suggested_action,
        )

        existing = self.events.get(
            key
        )

        # ------------------------------------------------------------------
        # Existing incident within cooldown.
        # ------------------------------------------------------------------

        if (
            existing is not None
            and (
                now
                - existing.last_seen
                <= self.cooldown_seconds
            )
        ):

            existing.last_seen = now

            existing.occurrence_count += 1

            existing.risk_score = max(
                existing.risk_score,
                float(risk_score),
            )

            existing.reasons = (
                self._merge_reasons(
                    existing.reasons,
                    reasons,
                )
            )

            # Return False because this is a repeated occurrence.
            return (
                existing,
                False,
            )

        # ------------------------------------------------------------------
        # New correlated incident.
        # ------------------------------------------------------------------

        incident = CorrelatedIncident(
            key=key,

            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,

            severity=severity,

            suggested_action=(
                suggested_action
            ),

            risk_score=float(
                risk_score
            ),

            first_seen=now,
            last_seen=now,

            occurrence_count=1,

            reasons=list(
                reasons
            ),
        )

        self.events[key] = incident

        self.cleanup(
            now=now
        )

        return (
            incident,
            True,
        )

    def cleanup(
        self,
        now: Optional[float] = None,
    ) -> None:

        current = (
            now
            if now is not None
            else time.time()
        )

        expired = []

        for key, incident in (
            self.events.items()
        ):

            if (
                current
                - incident.last_seen
                > self.cooldown_seconds
            ):
                expired.append(
                    key
                )

        for key in expired:
            self.events.pop(
                key,
                None,
            )