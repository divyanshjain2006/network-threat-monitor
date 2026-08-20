"""
simulation_command_listener.py

Receives safe simulation commands from the central backend.

Flow:

    React
      ↓
    Express
      ↓
    Socket.io
      ↓
    Python edge agent

This module only controls synthetic simulation scenarios.
It does NOT execute real attacks.
"""

from __future__ import annotations

import logging
import threading
from typing import Callable

import socketio


logger = logging.getLogger(__name__)


ALLOWED_SCENARIOS = {
    "normal_web",
    "normal_dns",
    "normal_api",
    "traffic_burst",
    "destination_sweep",
    "connection_flood",
}


class SimulationCommandListener:
    """
    Listens for simulation commands from the backend.

    The listener runs in a background thread so it does not block
    the packet/flow processing loop.
    """

    def __init__(
        self,
        backend_url: str,
        scenario_callback: Callable[[str], None],
    ):
        self.backend_url = (
            backend_url.rstrip("/")
        )

        self.scenario_callback = (
            scenario_callback
        )

        self.client = socketio.Client(
            reconnection=True,
            reconnection_attempts=0,
            reconnection_delay=1,
            reconnection_delay_max=5,
        )

        self._thread = None

        self._register_handlers()

    # ------------------------------------------------------------------
    # Socket event handlers
    # ------------------------------------------------------------------

    def _register_handlers(self) -> None:

        @self.client.event
        def connect():
            logger.info(
                "Simulation command channel connected to backend."
            )

        @self.client.event
        def disconnect():
            logger.warning(
                "Simulation command channel disconnected."
            )

        @self.client.event
        def connect_error(error):
            logger.warning(
                "Simulation command channel connection error: %s",
                error,
            )

        @self.client.on(
            "simulation_scenario"
        )
        def simulation_scenario(data):
            try:
                if not isinstance(
                    data,
                    dict,
                ):
                    logger.warning(
                        "Invalid simulation command payload."
                    )
                    return

                scenario = str(
                    data.get(
                        "scenario",
                        "",
                    )
                ).strip().lower()

                if scenario not in ALLOWED_SCENARIOS:
                    logger.warning(
                        "Rejected unsupported simulation scenario: %s",
                        scenario,
                    )
                    return

                logger.info(
                    "Simulation command received: %s",
                    scenario.upper(),
                )

                self.scenario_callback(
                    scenario
                )

            except Exception:
                logger.exception(
                    "Failed to process simulation command."
                )

    # ------------------------------------------------------------------
    # Start
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        Start Socket.io connection in a daemon thread.
        """

        if self._thread is not None:
            return

        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="simulation-command-listener",
        )

        self._thread.start()

    def _run(self) -> None:

        try:
            self.client.connect(
                self.backend_url,
                transports=[
                    "websocket",
                    "polling",
                ],
            )

            self.client.wait()

        except Exception:
            logger.exception(
                "Simulation command listener stopped."
            )

    # ------------------------------------------------------------------
    # Stop
    # ------------------------------------------------------------------

    def stop(self) -> None:

        try:
            if self.client.connected:
                self.client.disconnect()
        except Exception:
            logger.exception(
                "Failed to stop simulation command listener."
            )