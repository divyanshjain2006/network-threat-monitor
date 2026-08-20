"""
main.py

Entry point for the Zero-Trust local edge agent.

Responsibilities:

    1. Load configuration.
    2. Load the ML model.
    3. Create the alert emitter.
    4. Create the NetworkSniffer.
    5. Start the optional simulation command listener.
    6. Start the sniffer.
    7. Shut down cleanly.

Architecture:

    main.py
       |
       +--> isolation_forest.py
       |
       +--> emitter.py
       |
       +--> telemetry_emitter.py
       |
       +--> incident_emitter.py
       |
       +--> simulation_command_listener.py
       |
       +--> sniffer.py
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import yaml
from dotenv import load_dotenv

from emitter import AlertEmitter
from simulation_command_listener import (
    SimulationCommandListener,
)
from isolation_forest import initialize
from sniffer import NetworkSniffer


# ============================================================================
# Environment
# ============================================================================

load_dotenv()


# ============================================================================
# Logging
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================

def load_config() -> dict:
    """
    Load config.yaml from the local-sniffer-agent directory.
    """

    project_root = (
        Path(__file__)
        .resolve()
        .parent
        .parent
    )

    config_path = (
        project_root / "config.yaml"
    )

    if not config_path.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {config_path}"
        )

    with config_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        config = yaml.safe_load(file)

    if not isinstance(config, dict):
        raise ValueError(
            "config.yaml must contain a YAML object."
        )

    return config


# ============================================================================
# Backend URL handling
# ============================================================================

def get_alert_backend_url() -> str:
    """
    Read BACKEND_URL from environment.

    Expected form:

        http://127.0.0.1:5000/api/alerts

    or:

        https://example.com/api/alerts
    """

    backend_url = os.getenv(
        "BACKEND_URL"
    )

    if not backend_url:
        raise RuntimeError(
            "BACKEND_URL is not configured in .env"
        )

    backend_url = backend_url.strip()

    if not backend_url:
        raise RuntimeError(
            "BACKEND_URL is empty."
        )

    return backend_url


def get_backend_base_url(
    alert_url: str,
) -> str:
    """
    Convert:

        http://127.0.0.1:5000/api/alerts

    into:

        http://127.0.0.1:5000
    """

    marker = "/api/alerts"

    if marker in alert_url:
        return alert_url.rsplit(
            marker,
            1,
        )[0].rstrip("/")

    return alert_url.rstrip("/")


# ============================================================================
# Main
# ============================================================================

def main() -> None:
    config = load_config()

    project_root = (
        Path(__file__)
        .resolve()
        .parent
        .parent
    )

    # ------------------------------------------------------------------------
    # Configuration sections
    # ------------------------------------------------------------------------

    backend_config = config.get(
        "backend",
        {},
    )

    sniffer_config = config.get(
        "sniffer",
        {},
    )

    model_config = config.get(
        "model",
        {},
    )

    # ------------------------------------------------------------------------
    # Backend
    # ------------------------------------------------------------------------

    alert_backend_url = (
        get_alert_backend_url()
    )

    backend_base_url = (
        get_backend_base_url(
            alert_backend_url
        )
    )

    logger.info(
        "Alert backend configured: %s",
        alert_backend_url,
    )

    # ------------------------------------------------------------------------
    # Model path
    # ------------------------------------------------------------------------

    configured_model_path = (
        model_config.get(
            "path",
            "models/isolation_forest.joblib",
        )
    )

    model_path = (
        project_root
        / configured_model_path
    )

    if not model_path.exists():
        raise FileNotFoundError(
            f"Isolation Forest model not found: "
            f"{model_path}"
        )

    # ------------------------------------------------------------------------
    # Initialize ML engine
    # ------------------------------------------------------------------------

    logger.info(
        "Loading Isolation Forest model from %s",
        model_path,
    )

    initialize(
        model_path=str(
            model_path
        )
    )

    logger.info(
        "Isolation Forest model loaded."
    )

    # ------------------------------------------------------------------------
    # Alert emitter
    # ------------------------------------------------------------------------

    emitter = AlertEmitter(
        timeout=backend_config.get(
            "timeout_seconds",
            5,
        )
    )

    # ------------------------------------------------------------------------
    # Network sniffer
    # ------------------------------------------------------------------------

    sniffer = NetworkSniffer(
        emitter=emitter,

        batch_size=sniffer_config.get(
            "batch_size",
            50,
        ),

        batch_sleep_seconds=sniffer_config.get(
            "batch_sleep_seconds",
            0.05,
        ),

        interface=sniffer_config.get(
            "interface"
        ),

        model_path=str(
            model_path
        ),

        mode=sniffer_config.get(
            "mode",
            "simulation",
        ),

        window_seconds=sniffer_config.get(
            "window_seconds",
            10.0,
        ),
    )

    logger.info(
        "Zero-Trust local edge agent started."
    )

    logger.info(
        "Sniffer mode: %s",
        sniffer.mode,
    )

    # ------------------------------------------------------------------------
    # Simulation command listener
    # ------------------------------------------------------------------------
    #
    # Only needed in simulation mode.
    #
    # The React dashboard sends:
    #
    #   POST /api/simulator/scenario
    #
    # Express emits:
    #
    #   simulation_scenario
    #
    # This listener receives the event and queues the scenario in the
    # NetworkSniffer.
    # ------------------------------------------------------------------------

    command_listener = None

    if sniffer.mode == "simulation":

        logger.info(
            "Initializing simulation command channel..."
        )

        command_listener = (
            SimulationCommandListener(
                backend_url=backend_base_url,

                scenario_callback=(
                    sniffer.queue_simulation_scenario
                ),
            )
        )

        command_listener.start()

        logger.info(
            "Simulation command listener started."
        )

    # ------------------------------------------------------------------------
    # Start sniffer
    # ------------------------------------------------------------------------

    try:

        sniffer.start()

    except KeyboardInterrupt:

        logger.info(
            "Edge agent stopped by user."
        )

    except Exception:

        logger.exception(
            "Edge agent terminated unexpectedly."
        )

        raise

    finally:

        if command_listener is not None:

            logger.info(
                "Stopping simulation command listener..."
            )

            command_listener.stop()

            logger.info(
                "Simulation command listener stopped."
            )


# ============================================================================
# Entry point
# ============================================================================

if __name__ == "__main__":
    main()