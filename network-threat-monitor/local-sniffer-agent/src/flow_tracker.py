"""
flow_tracker.py

Tracks network flows and device-level traffic.

The important improvement in this version is directional accounting:

    inbound traffic
    outbound traffic

The tracker determines direction using the local device IP.

This allows the telemetry layer to report:

    bytes_in
    bytes_out
    bytes_per_second_in
    bytes_per_second_out
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple
import time


FlowKey = Tuple[
    str,                 # src_ip
    str,                 # dst_ip
    str,                 # protocol
    Optional[int],       # src_port
    Optional[int],       # dst_port
]


@dataclass
class FlowStats:
    """
    Statistics for one directional flow.
    """

    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int]
    dst_port: Optional[int]

    first_seen: float
    last_seen: float

    packet_count: int = 0
    total_bytes: int = 0

    def add_packet(
        self,
        packet_size: int,
        timestamp: Optional[float] = None,
    ) -> None:

        now = (
            timestamp
            if timestamp is not None
            else time.time()
        )

        self.packet_count += 1
        self.total_bytes += int(packet_size)
        self.last_seen = now

    @property
    def duration(self) -> float:
        return max(
            self.last_seen - self.first_seen,
            0.001,
        )

    @property
    def average_packet_size(self) -> float:
        if self.packet_count == 0:
            return 0.0

        return (
            self.total_bytes
            / self.packet_count
        )

    @property
    def packets_per_second(self) -> float:
        return (
            self.packet_count
            / self.duration
        )

    @property
    def bytes_per_second(self) -> float:
        return (
            self.total_bytes
            / self.duration
        )


@dataclass
class DeviceWindow:
    """
    Device-level statistics for one telemetry window.
    """

    device_ip: str

    packets_in: int = 0
    packets_out: int = 0

    bytes_in: int = 0
    bytes_out: int = 0

    destinations: set[str] = field(
        default_factory=set
    )

    destination_ports: set[int] = field(
        default_factory=set
    )

    source_ports: set[int] = field(
        default_factory=set
    )

    protocols: set[str] = field(
        default_factory=set
    )

    inbound_flows: int = 0
    outbound_flows: int = 0

    # -----------------------------------------------------------------------
    # Backward-compatible total flow count
    # -----------------------------------------------------------------------

    @property
    def flows(self) -> int:
        return (
            self.inbound_flows
            + self.outbound_flows
        )

    # -----------------------------------------------------------------------
    # Directional rates
    # -----------------------------------------------------------------------

    def bytes_per_second_in(
        self,
        window_seconds: float,
    ) -> float:

        return (
            self.bytes_in
            / max(
                window_seconds,
                0.001,
            )
        )

    def bytes_per_second_out(
        self,
        window_seconds: float,
    ) -> float:

        return (
            self.bytes_out
            / max(
                window_seconds,
                0.001,
            )
        )

    # -----------------------------------------------------------------------
    # Add a flow
    # -----------------------------------------------------------------------

    def add_flow(
        self,
        flow: FlowStats,
        local_ip: str,
    ) -> None:

        self.protocols.add(
            flow.protocol
        )

        if flow.src_port is not None:
            self.source_ports.add(
                int(flow.src_port)
            )

        if flow.dst_port is not None:
            self.destination_ports.add(
                int(flow.dst_port)
            )

        # ---------------------------------------------------------------
        # OUTBOUND
        # ---------------------------------------------------------------

        if flow.src_ip == local_ip:

            self.packets_out += (
                flow.packet_count
            )

            self.bytes_out += (
                flow.total_bytes
            )

            self.outbound_flows += 1

            self.destinations.add(
                flow.dst_ip
            )

        # ---------------------------------------------------------------
        # INBOUND
        # ---------------------------------------------------------------

        elif flow.dst_ip == local_ip:

            self.packets_in += (
                flow.packet_count
            )

            self.bytes_in += (
                flow.total_bytes
            )

            self.inbound_flows += 1

            # For inbound traffic, the remote source is the
            # destination from the local device's perspective.
            self.destinations.add(
                flow.src_ip
            )


class FlowTracker:
    """
    Maintains active flows and closes them in fixed time windows.
    """

    def __init__(
        self,
        window_seconds: float = 10.0,
        local_ip: Optional[str] = None,
    ):
        self.window_seconds = max(
            1.0,
            float(window_seconds),
        )

        self.local_ip = local_ip

        self.flows: Dict[
            FlowKey,
            FlowStats,
        ] = {}

        self.window_started = time.time()

    # -----------------------------------------------------------------------
    # Update local IP
    # -----------------------------------------------------------------------

    def set_local_ip(
        self,
        local_ip: str,
    ) -> None:

        self.local_ip = local_ip

    # -----------------------------------------------------------------------
    # Add packet
    # -----------------------------------------------------------------------

    def add_packet(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        packet_size: int,
        timestamp: Optional[float] = None,
    ) -> None:

        now = (
            timestamp
            if timestamp is not None
            else time.time()
        )

        key = (
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
        )

        if key not in self.flows:

            self.flows[key] = FlowStats(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                src_port=src_port,
                dst_port=dst_port,
                first_seen=now,
                last_seen=now,
            )

        self.flows[key].add_packet(
            packet_size=packet_size,
            timestamp=now,
        )

    # -----------------------------------------------------------------------
    # Window check
    # -----------------------------------------------------------------------

    def window_complete(
        self,
        now: Optional[float] = None,
    ) -> bool:

        current = (
            now
            if now is not None
            else time.time()
        )

        return (
            current
            - self.window_started
            >= self.window_seconds
        )

    # -----------------------------------------------------------------------
    # Flush window
    # -----------------------------------------------------------------------

    def flush(
        self,
        now: Optional[float] = None,
    ):
        """
        Return:

            completed_flows
            device_windows
        """

        current = (
            now
            if now is not None
            else time.time()
        )

        completed_flows = self.flows

        device_windows: Dict[
            str,
            DeviceWindow,
        ] = {}

        # -------------------------------------------------------------------
        # If no local IP is configured, preserve previous behavior by
        # treating source IPs as devices.
        # -------------------------------------------------------------------

        for flow in completed_flows.values():

            device_ip = None

            if self.local_ip:

                if flow.src_ip == self.local_ip:
                    device_ip = self.local_ip

                elif flow.dst_ip == self.local_ip:
                    device_ip = self.local_ip

            else:
                device_ip = flow.src_ip

            if device_ip is None:
                continue

            device = device_windows.setdefault(
                device_ip,
                DeviceWindow(
                    device_ip=device_ip
                ),
            )

            device.add_flow(
                flow=flow,
                local_ip=device_ip,
            )

        # Reset window.
        self.flows = {}
        self.window_started = current

        return (
            completed_flows,
            device_windows,
        )