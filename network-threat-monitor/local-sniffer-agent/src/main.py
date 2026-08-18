"""
main.py

Entry point for the Zero-Trust local edge agent.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from emitter import AlertEmitter
from isolation_forest import initialize
from sniffer import NetworkSniffer


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def load_config() -> dict:
    """
    Load config.yaml from the local-sniffer-agent directory.

    main.py is inside src/, therefore:
        Path(__file__).parent.parent
    points to local-sniffer-agent/
    """

    project_root = Path(
        __file__
    ).resolve().parent.parent

    config_path = project_root / "config.yaml"

    if not config_path.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {config_path}"
        )

    with config_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        config = yaml.safe_load(file)

    return config


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    config = load_config()

    project_root = Path(
        __file__
    ).resolve().parent.parent

    # -----------------------------------------------------------------------
    # Read configuration
    # -----------------------------------------------------------------------

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

    # -----------------------------------------------------------------------
    # Resolve model path
    # -----------------------------------------------------------------------

    configured_model_path = model_config.get(
        "path",
        "models/isolation_forest.joblib",
    )

    model_path = (
        project_root / configured_model_path
    )

    # -----------------------------------------------------------------------
    # Initialize ML engine
    # -----------------------------------------------------------------------

    initialize(
        model_path=str(model_path),
        score_scale=model_config.get(
            "score_scale",
            3.0,
        ),
    )

    # -----------------------------------------------------------------------
    # Initialize backend emitter
    # -----------------------------------------------------------------------

    emitter = AlertEmitter(
        timeout=backend_config.get(
            "timeout_seconds",
            5,
        ),
    )

    # -----------------------------------------------------------------------
    # Initialize sniffer
    # -----------------------------------------------------------------------

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

        model_path=str(model_path),

        score_scale=model_config.get(
            "score_scale",
            3.0,
        ),

        mode=sniffer_config.get(
            "mode",
            "simulation",
        ),
    )

    # -----------------------------------------------------------------------
    # Start
    # -----------------------------------------------------------------------

    logger.info(
        "Zero-Trust local edge agent started."
    )

    logger.info(
        "Sniffer mode: %s",
        sniffer.mode,
    )

    sniffer.start()


if __name__ == "__main__":
    main()