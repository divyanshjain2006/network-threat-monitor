"""
attack_simulator.py

Development-only traffic scenario generator.

IMPORTANT:
This module does NOT perform real attacks.
It only generates synthetic network telemetry for testing
the detection pipeline in simulation mode.
"""

from __future__ import annotations

import random
from typing import Any, Dict, Iterable


class AttackSimulator:
    """
    Generates synthetic traffic patterns.

    The output has the same packet structure consumed by
    FlowTracker / NetworkSniffer.
    """

    SOURCE_IP = "192.168.1.100"

    NORMAL_DESTINATIONS = [
        "8.8.8.8",
        "1.1.1.1",
        "142.250.72.14",
        "151.101.1.69",
    ]

    # ------------------------------------------------------------------
    # Normal traffic
    # ------------------------------------------------------------------

    def normal_web(self) -> Iterable[Dict[str, Any]]:
        """
        Simulates ordinary HTTPS traffic.
        """

        destination = random.choice(
            self.NORMAL_DESTINATIONS
        )

        src_port = random.randint(
            1024,
            65535,
        )

        for _ in range(
            random.randint(12, 25)
        ):
            yield {
                "src_ip": self.SOURCE_IP,
                "dst_ip": destination,
                "protocol": "HTTPS",
                "src_port": src_port,
                "dst_port": 443,
                "packet_size": random.randint(
                    300,
                    1200,
                ),
            }

    def normal_dns(self) -> Iterable[Dict[str, Any]]:
        """
        Simulates ordinary DNS activity.
        """

        destination = random.choice(
            [
                "8.8.8.8",
                "1.1.1.1",
            ]
        )

        src_port = random.randint(
            1024,
            65535,
        )

        for _ in range(
            random.randint(5, 12)
        ):
            yield {
                "src_ip": self.SOURCE_IP,
                "dst_ip": destination,
                "protocol": "DNS",
                "src_port": src_port,
                "dst_port": 53,
                "packet_size": random.randint(
                    60,
                    500,
                ),
            }

    def normal_api(self) -> Iterable[Dict[str, Any]]:
        """
        Simulates ordinary API traffic.
        """

        destination = random.choice(
            self.NORMAL_DESTINATIONS
        )

        src_port = random.randint(
            1024,
            65535,
        )

        for _ in range(
            random.randint(15, 30)
        ):
            yield {
                "src_ip": self.SOURCE_IP,
                "dst_ip": destination,
                "protocol": "HTTPS",
                "src_port": src_port,
                "dst_port": 443,
                "packet_size": random.randint(
                    200,
                    1400,
                ),
            }

    # ------------------------------------------------------------------
    # Suspicious traffic
    # ------------------------------------------------------------------

    def traffic_burst(self) -> Iterable[Dict[str, Any]]:
        """
        Simulates a sudden high-volume traffic burst.
        """

        destination = random.choice(
            self.NORMAL_DESTINATIONS
        )

        src_port = random.randint(
            1024,
            65535,
        )

        for _ in range(
            random.randint(120, 220)
        ):
            yield {
                "src_ip": self.SOURCE_IP,
                "dst_ip": destination,
                "protocol": "TCP",
                "src_port": src_port,
                "dst_port": 443,
                "packet_size": random.randint(
                    900,
                    1500,
                ),
            }

    def connection_flood(self) -> Iterable[Dict[str, Any]]:
        """
        Simulates a large number of short-lived connections.

        This creates many distinct flows.
        """

        for _ in range(
            random.randint(60, 100)
        ):
            yield {
                "src_ip": self.SOURCE_IP,
                "dst_ip": random.choice(
                    self.NORMAL_DESTINATIONS
                ),
                "protocol": "TCP",
                "src_port": random.randint(
                    1024,
                    65535,
                ),
                "dst_port": random.randint(
                    1,
                    65535,
                ),
                "packet_size": random.randint(
                    60,
                    300,
                ),
            }

    def port_scan(self) -> Iterable[Dict[str, Any]]:
        """
        Simulates a scanning pattern across many destination ports.
        """

        destination = random.choice(
            self.NORMAL_DESTINATIONS
        )

        for destination_port in range(
            1,
            101,
        ):
            yield {
                "src_ip": self.SOURCE_IP,
                "dst_ip": destination,
                "protocol": "TCP",
                "src_port": random.randint(
                    1024,
                    65535,
                ),
                "dst_port": destination_port,
                "packet_size": random.randint(
                    60,
                    140,
                ),
            }

    def dns_anomaly(self) -> Iterable[Dict[str, Any]]:
        """
        Simulates unusually heavy DNS traffic.
        """

        for _ in range(
            random.randint(100, 180)
        ):
            yield {
                "src_ip": self.SOURCE_IP,
                "dst_ip": random.choice(
                    [
                        "8.8.8.8",
                        "1.1.1.1",
                    ]
                ),
                "protocol": "DNS",
                "src_port": random.randint(
                    1024,
                    65535,
                ),
                "dst_port": 53,
                "packet_size": random.randint(
                    500,
                    1500,
                ),
            }

    def data_exfiltration(self) -> Iterable[Dict[str, Any]]:
        """
        Simulates sustained large outbound transfers to an unusual
        destination.

        This is synthetic telemetry only; no data is actually transferred.
        """

        destination = "203.0.113.50"

        src_port = random.randint(
            1024,
            65535,
        )

        for _ in range(
            random.randint(120, 200)
        ):
            yield {
                "src_ip": self.SOURCE_IP,
                "dst_ip": destination,
                "protocol": "TCP",
                "src_port": src_port,
                "dst_port": 443,
                "packet_size": random.randint(
                    1200,
                    1500,
                ),
            }

    # ------------------------------------------------------------------
    # Scenario dispatcher
    # ------------------------------------------------------------------

    def generate(
        self,
        scenario: str,
    ) -> Iterable[Dict[str, Any]]:
        """
        Generate packets for the requested scenario.
        """

        scenario = scenario.strip().lower()

        scenarios = {
            "normal_web": self.normal_web,
            "normal_dns": self.normal_dns,
            "normal_api": self.normal_api,
            "traffic_burst": self.traffic_burst,
            "connection_flood": self.connection_flood,
            "port_scan": self.port_scan,
            "dns_anomaly": self.dns_anomaly,
            "data_exfiltration": self.data_exfiltration,
        }

        generator = scenarios.get(scenario)

        if generator is None:
            raise ValueError(
                f"Unknown simulation scenario: {scenario}"
            )

        return generator()