"""
telemetry_emitter.py

Sends device-level network telemetry to the central backend.

Telemetry is intentionally separate from the strict anomaly-alert contract.

Responsibilities:

    - identify the edge device
    - format telemetry
    - calculate local rates
    - POST to /api/telemetry
    - handle backend failures gracefully
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Optional

import requests
from dotenv import load_dotenv


logger = logging.getLogger(__name__)

load_dotenv()


class TelemetryEmitter:
    """
    Sends periodic device telemetry to the backend.
    """

    def __init__(
        self,
        backend_url: Optional[str] = None,
        timeout: float = 5.0,
        device_id: Optional[str] = None,
        hostname: Optional[str] = None,
    ):
        """
        Parameters:

            backend_url:
                Existing alert endpoint or backend URL.

            timeout:
                HTTP request timeout.

            device_id:
                Stable endpoint identity.

            hostname:
                Human-readable machine name.
        """

        alert_url = (
            backend_url
            or os.getenv(
                "BACKEND_URL"
            )
        )

        if not alert_url:
            raise ValueError(
                "BACKEND_URL is not configured."
            )

        alert_url = alert_url.strip()

        if not alert_url:
            raise ValueError(
                "BACKEND_URL is empty."
            )

        # -------------------------------------------------------------------
        # Convert:
        #
        # /api/alerts
        #
        # into:
        #
        # /api/telemetry
        # -------------------------------------------------------------------

        if "/api/alerts" in alert_url:

            base_url = (
                alert_url.rsplit(
                    "/api/alerts",
                    1
                )[0]
            )

        else:

            base_url = (
                alert_url.rstrip("/")
            )

        self.telemetry_url = (
            f"{base_url}/api/telemetry"
        )

        self.timeout = float(
            timeout
        )

        self.device_id = (
            device_id
            or os.getenv(
                "DEVICE_ID"
            )
            or "unknown-device"
        )

        self.hostname = (
            hostname
            or os.getenv(
                "DEVICE_HOSTNAME"
            )
            or "unknown-host"
        )

        self.session = (
            requests.Session()
        )

        self.session.headers.update(
            {
                "Content-Type":
                    "application/json",

                "Accept":
                    "application/json",
            }
        )

    # -----------------------------------------------------------------------
    # Rate helper
    # -----------------------------------------------------------------------

    @staticmethod
    def _rate(
        byte_count: int,
        interval_seconds: float,
    ) -> float:
        """
        Calculate bytes per second.
        """

        interval = max(
            float(
                interval_seconds
            ),
            0.001,
        )

        return (
            float(byte_count)
            / interval
        )

    # -----------------------------------------------------------------------
    # Emit
    # -----------------------------------------------------------------------

    def emit(
        self,
        src_ip: str,
        bytes_in: int,
        bytes_out: int,
        interval_seconds: float,
        packets: int,
        unique_destinations: int,
        flows: int,
    ) -> bool:
        """
        Send one telemetry snapshot.

        The backend also recalculates rates so the central system remains
        authoritative.
        """

        interval = max(
            float(
                interval_seconds
            ),
            0.001,
        )

        normalized_bytes_in = max(
            int(bytes_in),
            0,
        )

        normalized_bytes_out = max(
            int(bytes_out),
            0,
        )

        normalized_packets = max(
            int(packets),
            0,
        )

        normalized_destinations = max(
            int(
                unique_destinations
            ),
            0,
        )

        normalized_flows = max(
            int(flows),
            0,
        )

        total_bytes = (
            normalized_bytes_in
            + normalized_bytes_out
        )

        payload = {
            "device_id":
                self.device_id,

            "hostname":
                self.hostname,

            "src_ip":
                src_ip,

            "timestamp":
                (
                    datetime.now(
                        timezone.utc
                    )
                    .isoformat()
                    .replace(
                        "+00:00",
                        "Z",
                    )
                ),

            "bytes_in":
                normalized_bytes_in,

            "bytes_out":
                normalized_bytes_out,

            "interval_seconds":
                interval,

            "packets":
                normalized_packets,

            "unique_destinations":
                normalized_destinations,

            "flows":
                normalized_flows,

            "bytes_per_second_in":
                self._rate(
                    normalized_bytes_in,
                    interval,
                ),

            "bytes_per_second_out":
                self._rate(
                    normalized_bytes_out,
                    interval,
                ),

            "total_bytes":
                total_bytes,

            "total_bytes_per_second":
                self._rate(
                    total_bytes,
                    interval,
                ),
        }

        try:

            response = (
                self.session.post(
                    self.telemetry_url,
                    json=payload,
                    timeout=self.timeout,
                )
            )

            response.raise_for_status()

            logger.info(
                (
                    "Telemetry sent successfully. "
                    "HTTP %s"
                ),
                response.status_code,
            )

            return True

        except requests.Timeout:

            logger.warning(
                "Telemetry request timed out."
            )

            return False

        except requests.ConnectionError:

            logger.warning(
                "Unable to connect to telemetry backend."
            )

            return False

        except requests.RequestException as error:

            logger.warning(
                "Telemetry request failed: %s",
                error,
            )

            return False

        except Exception:

            logger.exception(
                "Unexpected telemetry error."
            )

            return False