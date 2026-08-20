"""
incident_emitter.py

Sends richer security incident information to the backend.

This is separate from emitter.py because the anomaly alert contract
is intentionally strict.
"""

from __future__ import annotations

import logging
import os
import socket
from typing import List

import requests
from dotenv import load_dotenv


load_dotenv()

logger = logging.getLogger(__name__)


class IncidentEmitter:

    def __init__(
        self,
        backend_url: str | None = None,
        timeout: float = 5.0,
    ):
        alert_url = (
            backend_url
            or os.getenv("BACKEND_URL")
        )

        if not alert_url:
            raise ValueError(
                "BACKEND_URL is not configured."
            )

        base_url = alert_url.rsplit(
            "/api/alerts",
            1
        )[0]

        self.incident_url = (
            f"{base_url}/api/incidents"
        )

        self.timeout = timeout

        self.device_id = socket.gethostname()
        self.hostname = socket.gethostname()

        self.session = requests.Session()

        self.session.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

    def emit(
        self,
        src_ip: str,
        risk_score: float,
        severity: str,
        suggested_action: str,
        reasons: List[str],
        attack_type: str = "UNKNOWN",
    ) -> bool:

        payload = {
            "device_id": self.device_id,
            "hostname": self.hostname,
            "src_ip": src_ip,
            "risk_score": float(risk_score),
            "severity": severity,
            "suggested_action": suggested_action,
            "reasons": reasons,
            "attack_type": attack_type,
        }

        try:
            response = self.session.post(
                self.incident_url,
                json=payload,
                timeout=self.timeout,
            )

            response.raise_for_status()

            logger.info(
                "Incident successfully created. HTTP %s",
                response.status_code,
            )

            return True

        except requests.RequestException as error:
            logger.warning(
                "Incident submission failed: %s",
                error,
            )

            return False