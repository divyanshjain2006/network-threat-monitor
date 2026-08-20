"""
sniffer.py

Flow-based Zero-Trust Network Threat Detection edge engine.

Pipeline:

    Packet capture / simulation
              |
              v
        FlowTracker
              |
              v
       10 ML features
              |
              v
       Isolation Forest
              |
              v
         Risk Engine
              |
              +----------------------+
              |                      |
              v                      v
           Alert                 Incident
              |                      |
              +----------+-----------+
                         |
                         v
                    SOC Backend

Additional protection:

    - Alert deduplication
    - Incident correlation
    - Flow-level high-throughput policy
    - Directional telemetry
"""

from __future__ import annotations

import logging
import queue
import random
import time
from typing import Any, Dict, Optional, Tuple

from scapy.all import (
    ICMP,
    IP,
    IPv6,
    TCP,
    UDP,
    sniff,
)

from device_identity import get_device_identity
from emitter import AlertEmitter
from flow_tracker import FlowTracker
from incident_correlator import IncidentCorrelator
from incident_emitter import IncidentEmitter
from isolation_forest import predict
from risk_engine import RiskEngine
from telemetry_emitter import TelemetryEmitter


logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================

DEFAULT_WINDOW_SECONDS = 10.0
DEFAULT_BATCH_SIZE = 50
DEFAULT_BATCH_SLEEP_SECONDS = 0.05

# Final risk required for an official alert.
ALERT_RISK_THRESHOLD = 70.0

# Same alert key will be suppressed for this many seconds.
ALERT_DEDUP_SECONDS = 5.0

# Same behavioral incident can be correlated for this long.
INCIDENT_CORRELATION_SECONDS = 30.0

# ---------------------------------------------------------------------------
# High-throughput flow policy
# ---------------------------------------------------------------------------

HIGH_FLOW_BPS_THRESHOLD = 100_000.0
SEVERE_FLOW_BPS_THRESHOLD = 500_000.0

HIGH_FLOW_ML_THRESHOLD = 70.0
SEVERE_FLOW_ML_THRESHOLD = 80.0


# =============================================================================
# Packet parsing
# =============================================================================

def get_protocol(packet) -> str:
    """
    Normalize a Scapy packet into a supported protocol label.
    """

    if packet.haslayer(ICMP):
        return "ICMP"

    if packet.haslayer(TCP):
        tcp = packet[TCP]

        ports = {
            int(tcp.sport),
            int(tcp.dport),
        }

        if 80 in ports:
            return "HTTP"

        if 443 in ports:
            return "HTTPS"

        return "TCP"

    if packet.haslayer(UDP):
        udp = packet[UDP]

        ports = {
            int(udp.sport),
            int(udp.dport),
        }

        if 53 in ports:
            return "DNS"

        return "UDP"

    return "UNKNOWN"


def extract_ips(
    packet,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract source and destination IP addresses.
    """

    if packet.haslayer(IP):
        layer = packet[IP]

        return (
            layer.src,
            layer.dst,
        )

    if packet.haslayer(IPv6):
        layer = packet[IPv6]

        return (
            layer.src,
            layer.dst,
        )

    return None, None


def extract_ports(
    packet,
) -> Tuple[Optional[int], Optional[int]]:
    """
    Extract TCP/UDP ports.
    """

    if packet.haslayer(TCP):
        layer = packet[TCP]

        return (
            int(layer.sport),
            int(layer.dport),
        )

    if packet.haslayer(UDP):
        layer = packet[UDP]

        return (
            int(layer.sport),
            int(layer.dport),
        )

    return None, None


def extract_packet_features(
    packet,
) -> Optional[Dict[str, Any]]:
    """
    Extract lightweight packet information.

    Packets are aggregated by FlowTracker before ML inference.
    """

    src_ip, dst_ip = extract_ips(packet)

    if not src_ip or not dst_ip:
        return None

    src_port, dst_port = extract_ports(packet)

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": get_protocol(packet),
        "src_port": src_port,
        "dst_port": dst_port,
        "packet_size": int(len(packet)),
    }


# =============================================================================
# Automatic background simulation
# =============================================================================

def choose_simulation_scenario() -> str:
    """
    Generate normal background traffic.

    Suspicious scenarios are triggered manually from the dashboard.
    """

    return random.choices(
        population=[
            "normal_web",
            "normal_dns",
            "normal_api",
        ],
        weights=[
            60,
            25,
            15,
        ],
        k=1,
    )[0]


# =============================================================================
# Main sniffer
# =============================================================================

class NetworkSniffer:
    """
    Main flow-based network monitoring engine.
    """

    def __init__(
        self,
        emitter: AlertEmitter,
        batch_size: int = DEFAULT_BATCH_SIZE,
        batch_sleep_seconds: float = (
            DEFAULT_BATCH_SLEEP_SECONDS
        ),
        interface: Optional[str] = None,
        model_path: str = (
            "models/isolation_forest.joblib"
        ),
        mode: str = "simulation",
        window_seconds: float = (
            DEFAULT_WINDOW_SECONDS
        ),
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

        self.mode = (
            str(mode)
            .strip()
            .lower()
        )

        if self.mode not in {
            "simulation",
            "live",
        }:
            raise ValueError(
                "sniffer.mode must be "
                "'simulation' or 'live'."
            )

        self.window_seconds = max(
            1.0,
            float(window_seconds),
        )

        # ---------------------------------------------------------------------
        # Endpoint identity
        # ---------------------------------------------------------------------

        self.device_identity = (
            get_device_identity()
        )

        logger.info(
            (
                "Device identity | "
                "id=%s | "
                "hostname=%s | "
                "local_ip=%s | "
                "platform=%s"
            ),
            self.device_identity["device_id"],
            self.device_identity["hostname"],
            self.device_identity["local_ip"],
            self.device_identity["platform"],
        )

        # ---------------------------------------------------------------------
        # Flow tracker
        # ---------------------------------------------------------------------

        self.flow_tracker = FlowTracker(
            window_seconds=self.window_seconds,
            local_ip=(
                self.device_identity["local_ip"]
            ),
        )

        # ---------------------------------------------------------------------
        # Risk engine
        # ---------------------------------------------------------------------

        self.risk_engine = RiskEngine()

        # ---------------------------------------------------------------------
        # Telemetry emitter
        # ---------------------------------------------------------------------

        self.telemetry_emitter = TelemetryEmitter(
            device_id=(
                self.device_identity["device_id"]
            ),
            hostname=(
                self.device_identity["hostname"]
            ),
        )

        # ---------------------------------------------------------------------
        # Incident emitter
        # ---------------------------------------------------------------------

        self.incident_emitter = IncidentEmitter()

        # ---------------------------------------------------------------------
        # Incident correlation
        # ---------------------------------------------------------------------

        self.incident_correlator = (
            IncidentCorrelator(
                cooldown_seconds=(
                    INCIDENT_CORRELATION_SECONDS
                )
            )
        )

        # ---------------------------------------------------------------------
        # Alert deduplication
        # ---------------------------------------------------------------------

        self.alert_dedup: dict[
            str,
            float,
        ] = {}

        # ---------------------------------------------------------------------
        # Dashboard-controlled simulation queue
        # ---------------------------------------------------------------------

        self.simulation_queue = (
            queue.Queue()
        )

        # ---------------------------------------------------------------------
        # Runtime counters
        # ---------------------------------------------------------------------

        self.packets_seen = 0
        self.packets_analyzed = 0
        self.flows_analyzed = 0
        self.anomalies_detected = 0
        self.telemetry_windows = 0
        self.alerts_emitted = 0
        self.alerts_suppressed = 0
        self.incidents_emitted = 0
        self.incidents_correlated = 0

    # =========================================================================
    # Dashboard command queue
    # =========================================================================

    def queue_simulation_scenario(
        self,
        scenario: str,
    ) -> None:
        """
        Queue a scenario received from the React dashboard.
        """

        scenario = (
            str(scenario)
            .strip()
            .lower()
        )

        allowed = {
            "normal_web",
            "normal_dns",
            "normal_api",
            "traffic_burst",
            "destination_sweep",
            "connection_flood",
            "data_exfiltration",
        }

        if scenario not in allowed:
            logger.warning(
                "Rejected unsupported simulation scenario: %s",
                scenario,
            )
            return

        self.simulation_queue.put(
            scenario
        )

        logger.warning(
            "Dashboard simulation command queued: %s",
            scenario.upper(),
        )

    # =========================================================================
    # Flow -> ML features
    # =========================================================================

    def flow_to_ml_features(
        self,
        flow,
    ) -> Dict[str, Any]:
        """
        Convert FlowStats into the exact 10-feature ML input structure.
        """

        return {
            "packet_count": int(
                flow.packet_count
            ),
            "total_bytes": int(
                flow.total_bytes
            ),
            "average_packet_size": float(
                flow.average_packet_size
            ),
            "packets_per_second": float(
                flow.packets_per_second
            ),
            "bytes_per_second": float(
                flow.bytes_per_second
            ),
            "src_port": (
                int(flow.src_port)
                if flow.src_port is not None
                else 0
            ),
            "dst_port": (
                int(flow.dst_port)
                if flow.dst_port is not None
                else 0
            ),
            "unique_destinations": 1,
            "unique_destination_ports": (
                1
                if flow.dst_port is not None
                else 0
            ),
            "protocol": flow.protocol,
        }

    # =========================================================================
    # Packet -> FlowTracker
    # =========================================================================

    def add_packet_to_tracker(
        self,
        packet_data: Dict[str, Any],
    ) -> None:
        """
        Add one packet to the current flow window.
        """

        self.flow_tracker.add_packet(
            src_ip=packet_data["src_ip"],
            dst_ip=packet_data["dst_ip"],
            protocol=packet_data["protocol"],
            src_port=packet_data["src_port"],
            dst_port=packet_data["dst_port"],
            packet_size=packet_data["packet_size"],
        )

        self.packets_analyzed += 1

    # =========================================================================
    # Alert deduplication
    # =========================================================================

    def _alert_key(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        action: str,
    ) -> str:
        """
        Generate a stable deduplication key.
        """

        return "|".join(
            [
                str(src_ip),
                str(dst_ip),
                str(protocol).upper(),
                str(action).upper(),
            ]
        )

    def _should_suppress_alert(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        action: str,
    ) -> bool:
        """
        Suppress repeated identical alerts within the cooldown window.
        """

        now = time.time()

        key = self._alert_key(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            action=action,
        )

        previous = self.alert_dedup.get(
            key
        )

        if (
            previous is not None
            and (
                now - previous
                < ALERT_DEDUP_SECONDS
            )
        ):
            self.alerts_suppressed += 1

            logger.info(
                (
                    "Duplicate alert suppressed | "
                    "device=%s | "
                    "destination=%s | "
                    "protocol=%s | "
                    "action=%s"
                ),
                src_ip,
                dst_ip,
                protocol,
                action,
            )

            return True

        self.alert_dedup[key] = now

        return False

    def _cleanup_alert_dedup(self) -> None:
        """
        Remove expired alert deduplication entries.
        """

        now = time.time()

        expired = [
            key
            for key, timestamp
            in self.alert_dedup.items()
            if now - timestamp
            > ALERT_DEDUP_SECONDS * 2
        ]

        for key in expired:
            self.alert_dedup.pop(
                key,
                None,
            )

    # =========================================================================
    # Flow-level policy
    # =========================================================================

    def apply_flow_policy(
        self,
        ml_score: float,
        flow_bytes_per_second: float,
        current_risk: float,
        severity: str,
        action: str,
        reasons: list[str],
    ) -> tuple[
        float,
        str,
        str,
        list[str],
    ]:
        """
        Apply a deterministic Zero-Trust policy for a very high-throughput
        suspicious individual flow.

        Both ML suspicion and throughput are required.
        """

        risk = float(
            current_risk
        )

        flow_rate = max(
            0.0,
            float(
                flow_bytes_per_second
            ),
        )

        ml = max(
            0.0,
            min(
                100.0,
                float(ml_score),
            ),
        )

        # ---------------------------------------------------------------------
        # Severe suspicious flow
        # ---------------------------------------------------------------------

        if (
            flow_rate >=
            SEVERE_FLOW_BPS_THRESHOLD
            and ml >=
            SEVERE_FLOW_ML_THRESHOLD
        ):
            # Don't force every severe event to exactly 85.
            # Preserve useful risk variation.
            policy_bonus = min(
                15.0,
                (
                    (flow_rate
                     / SEVERE_FLOW_BPS_THRESHOLD)
                    * 5.0
                ),
            )

            risk = max(
                risk,
                85.0 + policy_bonus,
            )

            reason = (
                "Extremely high sustained "
                "suspicious flow detected."
            )

            if reason not in reasons:
                reasons.append(
                    reason
                )

        # ---------------------------------------------------------------------
        # High suspicious flow
        # ---------------------------------------------------------------------

        elif (
            flow_rate >=
            HIGH_FLOW_BPS_THRESHOLD
            and ml >=
            HIGH_FLOW_ML_THRESHOLD
        ):
            # Start at 70 but allow higher ML/rate to increase the score.
            ml_bonus = (
                max(
                    0.0,
                    ml - HIGH_FLOW_ML_THRESHOLD,
                )
                * 0.50
            )

            rate_bonus = min(
                8.0,
                (
                    flow_rate
                    / 1_000_000.0
                )
                * 8.0,
            )

            risk = max(
                risk,
                70.0
                + ml_bonus
                + rate_bonus,
            )

            reason = (
                "High-volume suspicious "
                "flow detected."
            )

            if reason not in reasons:
                reasons.append(
                    reason
                )

        # ---------------------------------------------------------------------
        # Derive policy from final score.
        # ---------------------------------------------------------------------

        if risk >= 90.0:

            severity = "CRITICAL"
            action = "QUARANTINE_DEVICE"

        elif risk >= 75.0:

            severity = "HIGH"
            action = "BLOCK"

        elif risk >= 50.0:

            severity = "MEDIUM"
            action = "REQUIRE_STEP_UP_AUTH"

        elif risk >= 25.0:

            severity = "LOW"
            action = "MONITOR"

        else:

            severity = "NORMAL"
            action = "ALLOW"

        return (
            round(
                min(
                    risk,
                    100.0,
                ),
                2,
            ),
            severity,
            action,
            reasons,
        )

    # =========================================================================
    # Analyze completed flows
    # =========================================================================

    def analyze_completed_flows(
        self,
        flows,
        devices,
    ) -> None:
        """
        Analyze all completed flows.

        Device-level and flow-level context are combined.
        """

        # ---------------------------------------------------------------------
        # Device context
        # ---------------------------------------------------------------------

        device_context = {}

        for device_ip, stats in devices.items():

            total_bytes = (
                stats.bytes_in
                + stats.bytes_out
            )

            device_bytes_per_second = (
                total_bytes
                / max(
                    self.window_seconds,
                    0.001,
                )
            )

            device_context[device_ip] = {
                "bytes_per_second":
                    device_bytes_per_second,

                "bytes_per_second_in":
                    stats.bytes_per_second_in(
                        self.window_seconds
                    ),

                "bytes_per_second_out":
                    stats.bytes_per_second_out(
                        self.window_seconds
                    ),

                "bytes_in":
                    stats.bytes_in,

                "bytes_out":
                    stats.bytes_out,

                "unique_destinations":
                    len(
                        stats.destinations
                    ),

                "flows":
                    stats.flows,
            }

        # ---------------------------------------------------------------------
        # Flow analysis
        # ---------------------------------------------------------------------

        for flow in flows.values():

            self.flows_analyzed += 1

            features = (
                self.flow_to_ml_features(
                    flow
                )
            )

            try:

                # =============================================================
                # 1. ML
                # =============================================================

                ml_result = predict(
                    features
                )

                ml_threat_score = float(
                    ml_result["threat_score"]
                )

                ml_anomaly = bool(
                    ml_result["anomaly_flag"]
                )

                raw_decision_score = float(
                    ml_result.get(
                        "raw_decision_score",
                        0.0,
                    )
                )

                # =============================================================
                # 2. Device context
                # =============================================================

                context = device_context.get(
                    flow.src_ip,
                    {
                        "bytes_per_second": 0.0,
                        "bytes_per_second_in": 0.0,
                        "bytes_per_second_out": 0.0,
                        "bytes_in": 0,
                        "bytes_out": 0,
                        "unique_destinations": 0,
                        "flows": 0,
                    },
                )

                # =============================================================
                # 3. Flow context
                # =============================================================

                flow_bytes_per_second = float(
                    flow.bytes_per_second
                )

                device_bytes_per_second = float(
                    context[
                        "bytes_per_second"
                    ]
                )

                effective_bytes_per_second = max(
                    flow_bytes_per_second,
                    device_bytes_per_second,
                )

                # =============================================================
                # 4. Risk engine
                # =============================================================

                risk_result = (
                    self.risk_engine.evaluate(
                        ml_threat_score=(
                            ml_threat_score
                        ),
                        bytes_per_second=(
                            effective_bytes_per_second
                        ),
                        unique_destinations=(
                            context[
                                "unique_destinations"
                            ]
                        ),
                        flows=(
                            context["flows"]
                        ),
                    )
                )

                final_risk = float(
                    risk_result.risk_score
                )

                final_severity = (
                    risk_result.severity
                )

                final_action = (
                    risk_result.suggested_action
                )

                final_reasons = list(
                    risk_result.reasons
                )

                # =============================================================
                # 5. Flow-level policy
                # =============================================================

                (
                    final_risk,
                    final_severity,
                    final_action,
                    final_reasons,
                ) = self.apply_flow_policy(
                    ml_score=ml_threat_score,
                    flow_bytes_per_second=(
                        flow_bytes_per_second
                    ),
                    current_risk=final_risk,
                    severity=final_severity,
                    action=final_action,
                    reasons=final_reasons,
                )

                # =============================================================
                # 6. Clean logging
                # =============================================================

                logger.info(
                    (
                        "Risk evaluation | "
                        "device=%s | "
                        "flow=%s->%s | "
                        "protocol=%s | "
                        "ML=%.2f | "
                        "RAW=%.6f | "
                        "FLOW_BPS=%.2f | "
                        "DEVICE_BPS=%.2f | "
                        "RISK=%.2f | "
                        "severity=%s | "
                        "action=%s"
                    ),
                    flow.src_ip,
                    flow.src_ip,
                    flow.dst_ip,
                    flow.protocol,
                    ml_threat_score,
                    raw_decision_score,
                    flow_bytes_per_second,
                    device_bytes_per_second,
                    final_risk,
                    final_severity,
                    final_action,
                )

                for reason in final_reasons:

                    logger.info(
                        "Risk reason | device=%s | %s",
                        flow.src_ip,
                        reason,
                    )

                # =============================================================
                # 7. Final alert threshold
                # =============================================================

                if (
                    final_risk
                    < ALERT_RISK_THRESHOLD
                ):
                    logger.info(
                        (
                            "Below alert threshold | "
                            "device=%s | "
                            "ML=%.2f | "
                            "RISK=%.2f | "
                            "ML anomaly=%s"
                        ),
                        flow.src_ip,
                        ml_threat_score,
                        final_risk,
                        ml_anomaly,
                    )

                    continue

                self.anomalies_detected += 1

                logger.warning(
                    (
                        "THREAT DETECTED | "
                        "%s -> %s | "
                        "protocol=%s | "
                        "bytes=%d | "
                        "packets=%d | "
                        "ML=%.2f | "
                        "RISK=%.2f | "
                        "severity=%s | "
                        "action=%s"
                    ),
                    flow.src_ip,
                    flow.dst_ip,
                    flow.protocol,
                    flow.total_bytes,
                    flow.packet_count,
                    ml_threat_score,
                    final_risk,
                    final_severity,
                    final_action,
                )

                # =============================================================
                # 8. ALERT DEDUPLICATION
                # =============================================================

                if self._should_suppress_alert(
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    protocol=flow.protocol,
                    action=final_action,
                ):
                    # Incident correlation is still handled separately.
                    pass

                else:

                    alert_sent = (
                        self.emitter.emit_anomaly(
                            src_ip=flow.src_ip,
                            dst_ip=flow.dst_ip,
                            protocol=flow.protocol,
                            byte_count=int(
                                flow.total_bytes
                            ),
                            threat_score=float(
                                final_risk
                            ),
                            anomaly_flag=True,
                            suggested_action=(
                                final_action
                            ),
                        )
                    )

                    if alert_sent:
                        self.alerts_emitted += 1

                # =============================================================
                # 9. INCIDENT CORRELATION
                # =============================================================

                (
                    correlated_incident,
                    is_new_incident,
                ) = self.incident_correlator.observe(
                    src_ip=flow.src_ip,
                    dst_ip=flow.dst_ip,
                    protocol=flow.protocol,
                    risk_score=final_risk,
                    severity=final_severity,
                    suggested_action=final_action,
                    reasons=final_reasons,
                )

                if not is_new_incident:

                    self.incidents_correlated += 1

                    logger.info(
                        (
                            "Correlated threat occurrence | "
                            "device=%s | "
                            "destination=%s | "
                            "protocol=%s | "
                            "occurrences=%d"
                        ),
                        flow.src_ip,
                        flow.dst_ip,
                        flow.protocol,
                        (
                            correlated_incident
                            .occurrence_count
                        ),
                    )

                    # Do not create another backend incident.
                    continue

                # =============================================================
                # 10. Create ONE new incident
                # =============================================================

                incident_sent = (
                    self.incident_emitter.emit(
                        src_ip=(
                            correlated_incident.src_ip
                        ),

                        risk_score=(
                            correlated_incident.risk_score
                        ),

                        severity=(
                            correlated_incident.severity
                        ),

                        suggested_action=(
                            correlated_incident
                            .suggested_action
                        ),

                        reasons=(
                            correlated_incident
                            .reasons
                        ),

                        attack_type=(
                            "BEHAVIORAL_ANOMALY"
                        ),
                    )
                )

                if incident_sent:

                    self.incidents_emitted += 1

            except Exception:

                logger.exception(
                    "Failed to analyze completed flow."
                )

        # Clean old alert-dedup entries once per completed window.
        self._cleanup_alert_dedup()

    # =========================================================================
    # Device telemetry
    # =========================================================================

    def emit_device_telemetry(
        self,
        devices,
    ) -> None:
        """
        Send directional device telemetry.
        """

        for device_ip, stats in devices.items():

            try:

                bytes_in = int(
                    stats.bytes_in
                )

                bytes_out = int(
                    stats.bytes_out
                )

                packets_total = (
                    int(stats.packets_in)
                    + int(stats.packets_out)
                )

                unique_destinations = len(
                    stats.destinations
                )

                flows = int(
                    stats.flows
                )

                rate_in = (
                    stats.bytes_per_second_in(
                        self.window_seconds
                    )
                )

                rate_out = (
                    stats.bytes_per_second_out(
                        self.window_seconds
                    )
                )

                logger.info(
                    (
                        "Device traffic | "
                        "device=%s | "
                        "IN=%.2f B/s | "
                        "OUT=%.2f B/s | "
                        "bytes_in=%d | "
                        "bytes_out=%d"
                    ),
                    device_ip,
                    rate_in,
                    rate_out,
                    bytes_in,
                    bytes_out,
                )

                success = (
                    self.telemetry_emitter.emit(
                        src_ip=device_ip,
                        bytes_in=bytes_in,
                        bytes_out=bytes_out,
                        interval_seconds=(
                            self.window_seconds
                        ),
                        packets=packets_total,
                        unique_destinations=(
                            unique_destinations
                        ),
                        flows=flows,
                    )
                )

                if success:

                    logger.info(
                        (
                            "Telemetry | "
                            "device=%s | "
                            "IN=%.2f B/s | "
                            "OUT=%.2f B/s | "
                            "total=%d bytes | "
                            "flows=%d | "
                            "destinations=%d"
                        ),
                        device_ip,
                        rate_in,
                        rate_out,
                        bytes_in + bytes_out,
                        flows,
                        unique_destinations,
                    )

            except Exception:

                logger.exception(
                    "Failed to emit telemetry "
                    "for device %s.",
                    device_ip,
                )

    # =========================================================================
    # Flow window
    # =========================================================================

    def process_completed_window(
        self,
    ) -> None:
        """
        Flush the current FlowTracker window when complete.
        """

        if not self.flow_tracker.window_complete():
            return

        flows, devices = (
            self.flow_tracker.flush()
        )

        if not flows:
            return

        self.telemetry_windows += 1

        logger.info(
            (
                "Flow window completed | "
                "flows=%d | "
                "devices=%d"
            ),
            len(flows),
            len(devices),
        )

        self.analyze_completed_flows(
            flows,
            devices,
        )

        self.emit_device_telemetry(
            devices
        )

    # =========================================================================
    # Live Scapy callback
    # =========================================================================

    def process_packet(
        self,
        packet,
    ) -> None:
        """
        Process one real Scapy packet.
        """

        self.packets_seen += 1

        try:

            packet_data = (
                extract_packet_features(
                    packet
                )
            )

            if packet_data is None:
                return

            self.add_packet_to_tracker(
                packet_data
            )

            self.process_completed_window()

        except Exception:

            logger.exception(
                "Error processing captured packet."
            )

    # =========================================================================
    # Simulation packet
    # =========================================================================

    def process_simulated_packet(
        self,
        packet_data: Dict[str, Any],
    ) -> None:
        """
        Feed synthetic traffic through the same pipeline as live traffic.
        """

        self.packets_seen += 1

        try:

            self.add_packet_to_tracker(
                packet_data
            )

            self.process_completed_window()

        except Exception:

            logger.exception(
                "Error processing simulated packet."
            )

    # =========================================================================
    # Simulation scenario generation
    # =========================================================================

    def generate_simulated_flow(
        self,
        scenario: str,
    ) -> None:
        """
        Generate safe synthetic traffic.

        The source IP is the actual endpoint IP detected by device_identity.
        """

        src_ip = (
            self.device_identity[
                "local_ip"
            ]
        )

        normal_destinations = [
            "8.8.8.8",
            "1.1.1.1",
            "142.250.72.14",
            "151.101.1.69",
        ]

        # ---------------------------------------------------------------------
        # NORMAL WEB
        # ---------------------------------------------------------------------

        if scenario == "normal_web":

            dst_ip = random.choice(
                normal_destinations
            )

            protocol = "HTTPS"
            src_port = random.randint(
                1024,
                65535,
            )
            dst_port = 443

            packet_count = random.randint(
                10,
                20,
            )

            packet_size_range = (
                300,
                1000,
            )

            packet_delay_range = (
                0.05,
                0.12,
            )

        # ---------------------------------------------------------------------
        # NORMAL DNS
        # ---------------------------------------------------------------------

        elif scenario == "normal_dns":

            dst_ip = random.choice(
                [
                    "8.8.8.8",
                    "1.1.1.1",
                ]
            )

            protocol = "DNS"
            src_port = random.randint(
                1024,
                65535,
            )
            dst_port = 53

            packet_count = random.randint(
                4,
                10,
            )

            packet_size_range = (
                60,
                450,
            )

            packet_delay_range = (
                0.08,
                0.18,
            )

        # ---------------------------------------------------------------------
        # NORMAL API
        # ---------------------------------------------------------------------

        elif scenario == "normal_api":

            dst_ip = random.choice(
                normal_destinations
            )

            protocol = "HTTPS"
            src_port = random.randint(
                1024,
                65535,
            )
            dst_port = 443

            packet_count = random.randint(
                8,
                18,
            )

            packet_size_range = (
                200,
                1200,
            )

            packet_delay_range = (
                0.05,
                0.12,
            )

        # ---------------------------------------------------------------------
        # TRAFFIC BURST
        # ---------------------------------------------------------------------

        elif scenario == "traffic_burst":

            dst_ip = random.choice(
                normal_destinations
            )

            protocol = "TCP"
            src_port = random.randint(
                1024,
                65535,
            )
            dst_port = random.choice(
                [80, 443]
            )

            packet_count = random.randint(
                150,
                250,
            )

            packet_size_range = (
                900,
                1500,
            )

            packet_delay_range = (
                0.002,
                0.006,
            )

        # ---------------------------------------------------------------------
        # CONNECTION FLOOD
        # ---------------------------------------------------------------------

        elif scenario == "connection_flood":

            for _ in range(
                random.randint(
                    60,
                    100,
                )
            ):

                self.process_simulated_packet(
                    {
                        "src_ip": src_ip,
                        "dst_ip": random.choice(
                            normal_destinations
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
                )

                time.sleep(
                    random.uniform(
                        0.005,
                        0.015,
                    )
                )

            return

        # ---------------------------------------------------------------------
        # DESTINATION SWEEP
        # ---------------------------------------------------------------------

        elif scenario == "destination_sweep":

            destinations = [
                "10.0.0.1",
                "10.0.0.2",
                "10.0.0.3",
                "10.0.0.4",
                "10.0.0.5",
                "10.0.0.6",
                "10.0.0.7",
                "10.0.0.8",
                "10.0.0.9",
                "10.0.0.10",
            ]

            for destination in destinations:

                for _ in range(
                    random.randint(
                        2,
                        5,
                    )
                ):

                    self.process_simulated_packet(
                        {
                            "src_ip": src_ip,
                            "dst_ip": destination,
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
                    )

                    time.sleep(
                        random.uniform(
                            0.01,
                            0.03,
                        )
                    )

            return

        # ---------------------------------------------------------------------
        # DATA EXFILTRATION
        # ---------------------------------------------------------------------

        elif scenario == "data_exfiltration":

            # Documentation/example address used only by simulation.
            dst_ip = "203.0.113.50"

            protocol = "HTTPS"

            src_port = random.randint(
                1024,
                65535,
            )

            dst_port = 443

            packet_count = random.randint(
                350,
                500,
            )

            packet_size_range = (
                1300,
                1500,
            )

            packet_delay_range = (
                0.001,
                0.003,
            )

        else:

            raise ValueError(
                f"Unknown simulation scenario: {scenario}"
            )

        # ---------------------------------------------------------------------
        # Generate packets.
        # ---------------------------------------------------------------------

        for _ in range(
            packet_count
        ):

            self.process_simulated_packet(
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "packet_size": random.randint(
                        packet_size_range[0],
                        packet_size_range[1],
                    ),
                }
            )

            time.sleep(
                random.uniform(
                    packet_delay_range[0],
                    packet_delay_range[1],
                )
            )

    # =========================================================================
    # Simulation mode
    # =========================================================================

    def start_simulation(self) -> None:
        """
        Run normal background traffic and accept manual scenarios.
        """

        logger.warning(
            "SIMULATION MODE ENABLED."
        )

        logger.warning(
            "No real network packets are being captured."
        )

        logger.info(
            "Simulation flow window: %.1f seconds",
            self.window_seconds,
        )

        while True:

            try:

                # Manual scenario has priority.
                try:

                    scenario = (
                        self.simulation_queue.get_nowait()
                    )

                    logger.warning(
                        "MANUAL SIMULATION SCENARIO: %s",
                        scenario.upper(),
                    )

                except queue.Empty:

                    scenario = (
                        choose_simulation_scenario()
                    )

                    logger.info(
                        "Automatic scenario: %s",
                        scenario.upper(),
                    )

                self.generate_simulated_flow(
                    scenario
                )

                time.sleep(
                    random.uniform(
                        0.5,
                        1.5,
                    )
                )

            except KeyboardInterrupt:

                logger.info(
                    "Simulation stopped by user."
                )

                self.flush_remaining_data()

                break

            except Exception:

                logger.exception(
                    "Simulation error."
                )

                time.sleep(1.0)

    # =========================================================================
    # Live mode
    # =========================================================================

    def start_live(self) -> None:
        """
        Start real Scapy packet capture.

        Requires appropriate packet-capture privileges.
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

        logger.info(
            "Flow window: %.1f seconds",
            self.window_seconds,
        )

        while True:

            try:

                sniff(
                    iface=self.interface,
                    prn=self.process_packet,
                    count=self.batch_size,
                    store=False,
                )

                time.sleep(
                    self.batch_sleep_seconds
                )

                self.process_completed_window()

            except KeyboardInterrupt:

                logger.info(
                    "Live sniffer stopped by user."
                )

                self.flush_remaining_data()

                break

            except PermissionError:

                logger.error(
                    (
                        "Permission denied while opening "
                        "the network capture socket. "
                        "Run the edge agent on an endpoint "
                        "with packet-capture privileges."
                    )
                )

                break

            except Exception:

                logger.exception(
                    "Packet capture error."
                )

                time.sleep(1.0)

    # =========================================================================
    # Flush
    # =========================================================================

    def flush_remaining_data(
        self,
    ) -> None:
        """
        Process remaining flows when the agent stops.
        """

        try:

            flows, devices = (
                self.flow_tracker.flush()
            )

            if flows:

                self.analyze_completed_flows(
                    flows,
                    devices,
                )

                self.emit_device_telemetry(
                    devices
                )

        except Exception:

            logger.exception(
                "Failed to flush remaining flow data."
            )

    # =========================================================================
    # Start
    # =========================================================================

    def start(self) -> None:
        """
        Start the configured sniffer mode.
        """

        logger.info(
            "Starting network sniffer in %s mode...",
            self.mode,
        )

        if self.mode == "simulation":
            self.start_simulation()
        else:
            self.start_live()