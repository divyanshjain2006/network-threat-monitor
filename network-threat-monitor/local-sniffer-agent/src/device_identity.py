"""
device_identity.py

Provides identity information for the local edge endpoint.

The edge agent uses:

    device_id
    hostname
    local_ip
    platform

The device_id is deterministic for the current hostname so repeated
agent starts on the same machine use the same identifier.

NOTE:
For a production deployment, device identity should eventually be
provisioned securely by a central enrollment service.
"""

from __future__ import annotations

import hashlib
import platform
import socket
import uuid
from typing import Dict


# ---------------------------------------------------------------------------
# Hostname
# ---------------------------------------------------------------------------

def get_hostname() -> str:
    """
    Return the current machine hostname.
    """

    hostname = socket.gethostname()

    return (
        hostname.strip()
        if hostname
        else "unknown-device"
    )


# ---------------------------------------------------------------------------
# Device ID
# ---------------------------------------------------------------------------

def get_device_id(
    hostname: str | None = None,
) -> str:
    """
    Generate a deterministic device identifier from the hostname.

    UUID5 is used so restarting the agent does not create a new device ID.
    """

    resolved_hostname = (
        hostname
        or get_hostname()
    )

    namespace = uuid.NAMESPACE_DNS

    identifier = uuid.uuid5(
        namespace,
        resolved_hostname,
    )

    return str(identifier)


# ---------------------------------------------------------------------------
# Local IP
# ---------------------------------------------------------------------------

def get_local_ip() -> str:
    """
    Determine the local IPv4 address used for normal outbound connectivity.

    This creates a UDP socket but does not send application data.

    Falls back to 127.0.0.1 when no usable network address is available.
    """

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    )

    try:
        sock.connect(
            (
                "8.8.8.8",
                80,
            )
        )

        local_ip = sock.getsockname()[0]

        if local_ip:
            return local_ip

        return "127.0.0.1"

    except OSError:
        return "127.0.0.1"

    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Platform
# ---------------------------------------------------------------------------

def get_platform() -> str:
    """
    Return the operating system name.
    """

    return platform.system()


# ---------------------------------------------------------------------------
# Complete identity
# ---------------------------------------------------------------------------

def get_device_identity() -> Dict[str, str]:
    """
    Return the complete edge-device identity.
    """

    hostname = get_hostname()

    return {
        "device_id": get_device_id(
            hostname
        ),
        "hostname": hostname,
        "local_ip": get_local_ip(),
        "platform": get_platform(),
    }