"""
emitter.py

Sends detected network anomalies to the remote backend.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict

import requests
from dotenv import load_dotenv


# Load variables from local-sniffer-agent/.env
load_dotenv()


logger = logging.getLogger(__name__)


class AlertEmitter:
    """
    Sends alerts to the remote backend.

    BACKEND_URL is read from .env.
    """

    VALID_PROTOCOLS = {
        "TCP",
        "UDP",
        "ICMP",
        "HTTP",
        "HTTPS",
        "DNS",
        "TLS",
        "UNKNOWN",
    }

    VALID_ACTIONS = {
        "ALLOW",
        "MONITOR",
        "BLOCK",
        "QUARANTINE_DEVICE",
        "REQUIRE_STEP_UP_AUTH",
    }

    def __init__(
        self,
        backend_url: str | None = None,
        timeout: float = 5.0,
    ):
        self.backend_url = (
            backend_url
            or os.getenv("BACKEND_URL")
        )

        if not self.backend_url:
            raise ValueError(
                "BACKEND_URL is missing. "
                "Add it to local-sniffer-agent/.env"
            )

        self.timeout = timeout

        self.session = requests.Session()

        self.session.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "ZTNA-Local-Sniffer-Agent/1.0",
            }
        )

        logger.info(
            "Alert backend configured: %s",
            self.backend_url,
        )

    def _validate_ip(self, value: str) -> str:
        """Validate IPv4 or IPv6."""

        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(
                f"Invalid IP address: {value}"
            ) from exc

        return value

    def _validate_payload(
        self,
        payload: Dict[str, Any],
    ) -> None:
        """
        Make sure the payload matches contract.json.

        The contract contains exactly eight alert fields.
        """

        expected_fields = {
            "timestamp",
            "src_ip",
            "dst_ip",
            "protocol",
            "byte_count",
            "threat_score",
            "anomaly_flag",
            "suggested_action",
        }

        if set(payload.keys()) != expected_fields:
            raise ValueError(
                "Payload does not match contract.json"
            )

        self._validate_ip(payload["src_ip"])
        self._validate_ip(payload["dst_ip"])

        if payload["protocol"] not in self.VALID_PROTOCOLS:
            raise ValueError(
                f"Invalid protocol: {payload['protocol']}"
            )

        if (
            not isinstance(payload["byte_count"], int)
            or payload["byte_count"] < 0
        ):
            raise ValueError(
                "byte_count must be a non-negative integer"
            )

        if not 0 <= payload["threat_score"] <= 100:
            raise ValueError(
                "threat_score must be between 0 and 100"
            )

        if not isinstance(
            payload["anomaly_flag"],
            bool,
        ):
            raise ValueError(
                "anomaly_flag must be boolean"
            )

        if payload["suggested_action"] not in self.VALID_ACTIONS:
            raise ValueError(
                f"Invalid suggested_action: "
                f"{payload['suggested_action']}"
            )

    def build_payload(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        byte_count: int,
        threat_score: float,
        anomaly_flag: bool,
        suggested_action: str,
    ) -> Dict[str, Any]:
        """
        Build the exact contract payload.
        """

        timestamp = (
            datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )

        payload = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "byte_count": int(byte_count),
            "threat_score": float(threat_score),
            "anomaly_flag": bool(anomaly_flag),
            "suggested_action": suggested_action,
        }

        self._validate_payload(payload)

        return payload

    def emit_anomaly(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        byte_count: int,
        threat_score: float,
        anomaly_flag: bool,
        suggested_action: str,
    ) -> bool:
        """Send one anomaly to the remote backend."""

        payload = self.build_payload(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            byte_count=byte_count,
            threat_score=threat_score,
            anomaly_flag=anomaly_flag,
            suggested_action=suggested_action,
        )

        try:
            response = self.session.post(
                self.backend_url,
                json=payload,
                timeout=self.timeout,
            )

            response.raise_for_status()

            logger.info(
                "Alert successfully sent to backend. HTTP %s",
                response.status_code,
            )

            return True

        except requests.Timeout:
            logger.warning(
                "Backend request timed out."
            )
            return False

        except requests.ConnectionError:
            logger.warning(
                "Could not connect to backend."
            )
            return False

        except requests.HTTPError as exc:
            logger.error(
                "Backend rejected alert: %s",
                exc,
            )
            return False

        except requests.RequestException as exc:
            logger.error(
                "HTTP request failed: %s",
                exc,
            )
            return False