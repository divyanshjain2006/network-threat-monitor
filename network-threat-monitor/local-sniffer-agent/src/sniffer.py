"""
sniffer.py

Zero-Trust local network traffic sniffer.

Modes:
    simulation
        Used for development/testing in GitHub Codespaces.
        Generates realistic-looking network feature data.

    live
        Uses Scapy to capture real network packets.

Pipeline:

    Network / Simulation
            ↓
       Feature extraction
            ↓
      Isolation Forest
            ↓
       anomaly_flag
       threat_score
            ↓
        emitter.py
            ↓
       Remote backend
"""

from __future__ import annotations

import logging
import random
import time
from typing import Any, Dict, Optional, Tuple

from scapy.all import ICMP, IP, IPv6, TCP, UDP, sniff

from emitter import AlertEmitter
from isolation_forest import initialize, predict


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def get_protocol(packet) -> str:
    """
    Convert Scapy packet layers into a protocol supported by contract.json.

    Supported contract values:
        TCP
        UDP
        ICMP
        HTTP
        HTTPS
        DNS
        TLS
        UNKNOWN
    """

    if packet.haslayer(TCP):
        return "TCP"

    if packet.haslayer(UDP):
        return "UDP"

    if packet.haslayer(ICMP):
        return "ICMP"

    return "UNKNOWN"


def extract_ips(
    packet,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract source and destination IP addresses.
    Supports IPv4 and IPv6.
    """

    if packet.haslayer(IP):
        layer = packet[IP]

        return layer.src, layer.dst

    if packet.haslayer(IPv6):
        layer = packet[IPv6]

        return layer.src, layer.dst

    return None, None


def extract_ports(
    packet,
) -> Tuple[Optional[int], Optional[int]]:
    """
    Extract source and destination ports.

    TCP/UDP have ports.
    ICMP and other protocols return None.
    """

    if packet.haslayer(TCP):
        layer = packet[TCP]

        return int(layer.sport), int(layer.dport)

    if packet.haslayer(UDP):
        layer = packet[UDP]

        return int(layer.sport), int(layer.dport)

    return None, None


def extract_features(
    packet,
) -> Optional[Dict[str, Any]]:
    """
    Convert a real Scapy packet into the numerical features expected
    by isolation_forest.py.
    """

    src_ip, dst_ip = extract_ips(packet)

    if not src_ip or not dst_ip:
        return None

    src_port, dst_port = extract_ports(packet)

    return {
        "packet_size": int(len(packet)),
        "protocol": get_protocol(packet),
        "src_port": src_port,
        "dst_port": dst_port,
    }


# ---------------------------------------------------------------------------
# Simulation mode
# ---------------------------------------------------------------------------

def generate_simulated_features() -> Dict[str, Any]:
    """
    Generate development-only network features.

    This does NOT capture real network traffic.

    It allows the complete:
        sniffer → ML → emitter → backend
    pipeline to be tested inside Codespaces.
    """

    protocols = [
        "TCP",
        "TCP",
        "TCP",
        "UDP",
        "ICMP",
        "DNS",
    ]

    return {
        "packet_size": random.randint(40, 1500),
        "protocol": random.choice(protocols),
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice(
            [
                22,
                53,
                80,
                443,
            ]
        ),
    }


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

def choose_action(
    threat_score: float,
) -> str:
    """
    Convert threat score into one of the actions allowed by contract.json.

    These thresholds are application policy and are NOT defined
    by contract.json itself.
    """

    if threat_score >= 90:
        return "QUARANTINE_DEVICE"

    if threat_score >= 75:
        return "BLOCK"

    if threat_score >= 50:
        return "REQUIRE_STEP_UP_AUTH"

    if threat_score >= 25:
        return "MONITOR"

    return "ALLOW"


# ---------------------------------------------------------------------------
# NetworkSniffer
# ---------------------------------------------------------------------------

class NetworkSniffer:
    """
    Main network monitoring class.

    Handles both simulation and real Scapy capture.
    """

    def __init__(
        self,
        emitter: AlertEmitter,
        batch_size: int = 50,
        batch_sleep_seconds: float = 0.05,
        interface: Optional[str] = None,
        model_path: str = "models/isolation_forest.joblib",
        score_scale: float = 3.0,
        mode: str = "simulation",
    ):
        self.emitter = emitter

        self.batch_size = max(
            1,
            int(batch_size),
        )

        self.batch_sleep_seconds = max(
            0.0,
            float(batch_sleep_seconds),
        )

        self.interface = interface

        self.mode = mode.lower().strip()

        if self.mode not in {"simulation", "live"}:
            raise ValueError(
                "sniffer.mode must be either "
                "'simulation' or 'live'."
            )

        # Load the Isolation Forest once.
        initialize(
            model_path=model_path,
            score_scale=score_scale,
        )

        self.packets_seen = 0
        self.packets_analyzed = 0
        self.anomalies_detected = 0

    # -----------------------------------------------------------------------
    # Common ML processing
    # -----------------------------------------------------------------------

    def analyze_features(
        self,
        features: Dict[str, Any],
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
    ) -> None:
        """
        Run Isolation Forest on a feature set.

        This method is shared by both simulation and live modes.
        """

        self.packets_seen += 1

        try:
            self.packets_analyzed += 1

            result = predict(features)

            anomaly_flag = bool(
                result["anomaly_flag"]
            )

            threat_score = float(
                result["threat_score"]
            )

            logger.info(
                "Traffic | protocol=%s | bytes=%d | "
                "score=%.2f | anomaly=%s",
                features["protocol"],
                features["packet_size"],
                threat_score,
                anomaly_flag,
            )

            if not anomaly_flag:
                return

            self.anomalies_detected += 1

            action = choose_action(
                threat_score
            )

            # Simulation mode needs example IPs because no real packet
            # exists from which to extract addresses.
            if src_ip is None:
                src_ip = "192.168.1.100"

            if dst_ip is None:
                dst_ip = "8.8.8.8"

            logger.warning(
                "ANOMALY DETECTED | %s -> %s | "
                "protocol=%s | bytes=%d | "
                "score=%.2f | action=%s",
                src_ip,
                dst_ip,
                features["protocol"],
                features["packet_size"],
                threat_score,
                action,
            )

            self.emitter.emit_anomaly(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=features["protocol"],
                byte_count=int(
                    features["packet_size"]
                ),
                threat_score=threat_score,
                anomaly_flag=True,
                suggested_action=action,
            )

        except Exception:
            logger.exception(
                "Error during ML analysis."
            )

    # -----------------------------------------------------------------------
    # Live packet callback
    # -----------------------------------------------------------------------

    def process_packet(
        self,
        packet,
    ) -> None:
        """
        Process one real Scapy packet.
        """

        try:
            features = extract_features(packet)

            if features is None:
                return

            src_ip, dst_ip = extract_ips(packet)

            self.analyze_features(
                features=features,
                src_ip=src_ip,
                dst_ip=dst_ip,
            )

        except Exception:
            logger.exception(
                "Error processing captured packet."
            )

    # -----------------------------------------------------------------------
    # Simulation
    # -----------------------------------------------------------------------

    def start_simulation(self) -> None:
        """
        Start development simulation.

        Useful in Codespaces where raw packet capture is unavailable.
        """

        logger.warning(
            "SIMULATION MODE ENABLED."
        )

        logger.warning(
            "No real network packets are being captured."
        )

        logger.info(
            "Generating simulated traffic every second..."
        )

        while True:
            try:
                features = generate_simulated_features()

                self.analyze_features(
                    features=features,
                    src_ip="192.168.1.100",
                    dst_ip="8.8.8.8",
                )

                time.sleep(1.0)

            except KeyboardInterrupt:
                logger.info(
                    "Simulation stopped by user."
                )
                break

            except Exception:
                logger.exception(
                    "Simulation error."
                )

                time.sleep(1.0)

    # -----------------------------------------------------------------------
    # Live Scapy capture
    # -----------------------------------------------------------------------

    def start_live(self) -> None:
        """
        Start real network packet capture.

        This requires appropriate OS/container packet-capture privileges.
        """

        logger.info(
            "Starting live Scapy capture..."
        )

        logger.info(
            "Interface: %s",
            self.interface or "Scapy default",
        )

        logger.info(
            "Batch size: %d",
            self.batch_size,
        )

        while True:
            try:
                sniff(
                    iface=self.interface,
                    prn=self.process_packet,
                    count=self.batch_size,
                    store=False,
                )

                # Small CPU yield after each batch.
                time.sleep(
                    self.batch_sleep_seconds
                )

            except KeyboardInterrupt:
                logger.info(
                    "Live sniffer stopped by user."
                )
                break

            except PermissionError:
                logger.error(
                    "Permission denied while opening the network "
                    "capture socket. Run the agent on a machine/container "
                    "with packet-capture privileges."
                )
                break

            except Exception:
                logger.exception(
                    "Packet capture error."
                )

                time.sleep(1.0)

    # -----------------------------------------------------------------------
    # Entry point
    # -----------------------------------------------------------------------

    def start(self) -> None:
        """
        Start the selected mode.
        """

        logger.info(
            "Starting network sniffer in %s mode...",
            self.mode,
        )

        if self.mode == "simulation":
            self.start_simulation()
        else:
            self.start_live()