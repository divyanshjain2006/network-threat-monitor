"""
isolation_forest.py

Runtime inference engine for the Zero-Trust edge agent.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np


logger = logging.getLogger(__name__)


DEFAULT_MODEL_PATH = (
    "models/isolation_forest.joblib"
)


PROTOCOL_TO_ID = {
    "UNKNOWN": 0,
    "TCP": 1,
    "UDP": 2,
    "ICMP": 3,
    "HTTP": 4,
    "HTTPS": 5,
    "DNS": 6,
    "TLS": 7,
}


class IsolationForestEngine:

    def __init__(
        self,
        model_path: str = DEFAULT_MODEL_PATH,
    ):
        self.model_path = Path(
            model_path
        )

        self.model = None
        self.scaler = None

        self.score_low = -0.5
        self.score_high = 0.5

        self.protocol_to_id = (
            PROTOCOL_TO_ID.copy()
        )

        self._load_model()

    def _load_model(self) -> None:

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Model not found: "
                f"{self.model_path}\n"
                "Run train_model.py first."
            )

        logger.info(
            "Loading Isolation Forest model "
            "from %s",
            self.model_path,
        )

        bundle = joblib.load(
            self.model_path
        )

        self.model = bundle["model"]
        self.scaler = bundle["scaler"]

        self.score_low = float(
            bundle.get(
                "normal_score_low",
                -0.5,
            )
        )

        self.score_high = float(
            bundle.get(
                "normal_score_high",
                0.5,
            )
        )

        self.protocol_to_id = bundle.get(
            "protocol_to_id",
            PROTOCOL_TO_ID,
        )

        logger.info(
            "Isolation Forest model loaded."
        )

    def _convert_features(
        self,
        features: Dict[str, Any],
    ) -> np.ndarray:

        packet_size = float(
            features.get(
                "packet_size",
                0,
            )
        )

        protocol = features.get(
            "protocol",
            "UNKNOWN",
        )

        protocol_id = self.protocol_to_id.get(
            protocol,
            self.protocol_to_id[
                "UNKNOWN"
            ],
        )

        src_port = features.get(
            "src_port"
        )

        dst_port = features.get(
            "dst_port"
        )

        if src_port is None:
            src_port = 0

        if dst_port is None:
            dst_port = 0

        return np.asarray(
            [
                [
                    packet_size,
                    protocol_id,
                    float(src_port),
                    float(dst_port),
                ]
            ],
            dtype=np.float64,
        )

    def _calculate_threat_score(
        self,
        decision_score: float,
    ) -> float:
        """
        Convert the Isolation Forest decision score
        into 0-100 threat score.

        Higher anomaly → higher threat score.
        """

        # Normal scores occupy approximately:
        #
        #     score_low → score_high
        #
        # Lower scores are more suspicious.

        if self.score_high <= self.score_low:
            return 50.0

        normalized_normality = (
            decision_score - self.score_low
        ) / (
            self.score_high
            - self.score_low
        )

        normalized_normality = max(
            0.0,
            min(
                1.0,
                normalized_normality,
            ),
        )

        threat_score = (
            1.0
            - normalized_normality
        ) * 100.0

        return float(
            max(
                0.0,
                min(
                    100.0,
                    threat_score,
                ),
            )
        )

    def predict(
        self,
        features: Dict[str, Any],
    ) -> Dict[str, Any]:

        vector = self._convert_features(
            features
        )

        scaled_vector = self.scaler.transform(
            vector
        )

        prediction = self.model.predict(
            scaled_vector
        )[0]

        decision_score = float(
            self.model.decision_function(
                scaled_vector
            )[0]
        )

        anomaly_flag = (
            prediction == -1
        )

        threat_score = (
            self._calculate_threat_score(
                decision_score
            )
        )

        return {
            "anomaly_flag": bool(
                anomaly_flag
            ),
            "threat_score": threat_score,
        }


_engine = None


def initialize(
    model_path: str = DEFAULT_MODEL_PATH,
) -> IsolationForestEngine:

    global _engine

    if _engine is None:
        _engine = IsolationForestEngine(
            model_path=model_path
        )

    return _engine


def predict(
    features: Dict[str, Any],
) -> Dict[str, Any]:

    global _engine

    if _engine is None:
        _engine = IsolationForestEngine()

    return _engine.predict(
        features
    )