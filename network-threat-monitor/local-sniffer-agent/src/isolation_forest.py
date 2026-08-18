"""
isolation_forest.py

Runtime inference layer for the Zero-Trust network anomaly detector.

Responsibilities:
1. Load the trained Isolation Forest model once.
2. Convert packet features into the exact training representation.
3. Run inference.
4. Convert the model's output into:
       anomaly_flag
       threat_score

The model itself is stored as a joblib bundle.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
import yaml


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Default values
# ---------------------------------------------------------------------------

DEFAULT_MODEL_PATH = "models/isolation_forest.joblib"

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


# ---------------------------------------------------------------------------
# Model runtime
# ---------------------------------------------------------------------------

class IsolationForestEngine:
    """
    Runtime wrapper around the trained Isolation Forest.

    The model is loaded exactly once and reused for every packet.
    This is important for performance.
    """

    def __init__(
        self,
        model_path: str = DEFAULT_MODEL_PATH,
        score_scale: float = 3.0,
    ):
        self.model_path = Path(model_path)
        self.score_scale = max(float(score_scale), 0.1)

        self.model = None
        self.scaler = None
        self.protocol_to_id = PROTOCOL_TO_ID.copy()

        self._load_model()

    def _load_model(self) -> None:
        """Load the model bundle from disk."""

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Trained model not found at: {self.model_path}\n"
                "Run train_model.py first."
            )

        logger.info(
            "Loading Isolation Forest model from %s",
            self.model_path,
        )

        bundle = joblib.load(self.model_path)

        self.model = bundle["model"]
        self.scaler = bundle["scaler"]

        if "protocol_to_id" in bundle:
            self.protocol_to_id = bundle["protocol_to_id"]

        logger.info("Isolation Forest model loaded.")

    # -----------------------------------------------------------------------
    # Feature conversion
    # -----------------------------------------------------------------------

    def _convert_features(
        self,
        features: Dict[str, Any],
    ) -> np.ndarray:
        """
        Convert the sniffer dictionary into the exact numerical vector
        used during training.
        """

        packet_size = float(
            features.get("packet_size", 0)
        )

        protocol = features.get(
            "protocol",
            "UNKNOWN",
        )

        protocol_id = self.protocol_to_id.get(
            protocol,
            self.protocol_to_id["UNKNOWN"],
        )

        src_port = features.get("src_port")

        if src_port is None:
            src_port = 0

        dst_port = features.get("dst_port")

        if dst_port is None:
            dst_port = 0

        vector = np.asarray(
            [
                [
                    packet_size,
                    float(protocol_id),
                    float(src_port),
                    float(dst_port),
                ]
            ],
            dtype=np.float64,
        )

        return vector

    # -----------------------------------------------------------------------
    # Threat score
    # -----------------------------------------------------------------------

    def _calculate_threat_score(
        self,
        decision_score: float,
    ) -> float:
        """
        Convert Isolation Forest's decision score into a human-friendly
        0-100 threat score.

        Isolation Forest's decision_function() is:
            higher -> more normal
            lower  -> more anomalous

        We therefore invert and scale it.

        IMPORTANT:
        This mapping is an engineering choice, not something specified
        by contract.json.
        """

        # Typical Isolation Forest scores are roughly centered around 0.
        #
        # Lower scores are more suspicious.
        normalized = (-decision_score) / self.score_scale

        # Map roughly [-1, +1] into [0, 100].
        threat_score = 50.0 + (
            normalized * 50.0
        )

        return float(
            max(
                0.0,
                min(
                    100.0,
                    threat_score,
                ),
            )
        )

    # -----------------------------------------------------------------------
    # Prediction
    # -----------------------------------------------------------------------

    def predict(
        self,
        features: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Run anomaly detection.

        Returns:

        {
            "anomaly_flag": bool,
            "threat_score": float
        }
        """

        vector = self._convert_features(features)

        scaled_vector = self.scaler.transform(vector)

        prediction = self.model.predict(
            scaled_vector
        )[0]

        decision_score = float(
            self.model.decision_function(
                scaled_vector
            )[0]
        )

        # Isolation Forest:
        #
        #   1  = normal
        #  -1  = anomaly
        anomaly_flag = prediction == -1

        threat_score = self._calculate_threat_score(
            decision_score
        )

        return {
            "anomaly_flag": bool(anomaly_flag),
            "threat_score": threat_score,
        }


# ---------------------------------------------------------------------------
# Singleton model engine
# ---------------------------------------------------------------------------

_engine = None


def initialize(
    model_path: str = DEFAULT_MODEL_PATH,
    score_scale: float = 3.0,
) -> IsolationForestEngine:
    """
    Initialize the shared ML engine.

    This should normally be called once when the application starts.
    """

    global _engine

    if _engine is None:
        _engine = IsolationForestEngine(
            model_path=model_path,
            score_scale=score_scale,
        )

    return _engine


def predict(
    features: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Public prediction function used by sniffer.py.

    Example:

        result = predict({
            "packet_size": 512,
            "protocol": "TCP",
            "src_port": 49220,
            "dst_port": 443,
        })

    Returns:

        {
            "anomaly_flag": False,
            "threat_score": 12.4
        }
    """

    global _engine

    if _engine is None:
        _engine = IsolationForestEngine()

    return _engine.predict(features)


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )

    engine = initialize()

    test_features = {
        "packet_size": 512,
        "protocol": "TCP",
        "src_port": 49152,
        "dst_port": 443,
    }

    result = engine.predict(
        test_features
    )

    print(result)