"""
isolation_forest.py

Loads the trained Isolation Forest and converts flow features into:

    anomaly_flag
    threat_score

The important design decision is:

    anomaly_flag
        comes from Isolation Forest's binary decision.

    threat_score
        comes from the raw decision_function() value and the calibrated
        normal score range saved by train_model.py.

This prevents every anomaly from becoming threat_score = 100.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np


# ---------------------------------------------------------------------------
# Global model state
# ---------------------------------------------------------------------------

_MODEL = None
_SCALER = None
_FEATURE_NAMES = None
_PROTOCOL_TO_ID = None

_NORMAL_SCORE_LOW = None
_NORMAL_SCORE_HIGH = None

_INITIALIZED = False


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

def initialize(
    model_path: str | Path,
) -> None:
    """
    Load the trained Isolation Forest bundle.

    Expected saved keys:

        model
        scaler
        feature_names
        protocol_to_id
        normal_score_low
        normal_score_high
    """

    global _MODEL
    global _SCALER
    global _FEATURE_NAMES
    global _PROTOCOL_TO_ID
    global _NORMAL_SCORE_LOW
    global _NORMAL_SCORE_HIGH
    global _INITIALIZED

    if _INITIALIZED:
        return

    model_path = Path(
        model_path
    )

    if not model_path.exists():
        raise FileNotFoundError(
            f"Model file not found: {model_path}"
        )

    bundle = joblib.load(
        model_path
    )

    required_keys = {
        "model",
        "scaler",
        "feature_names",
        "protocol_to_id",
        "normal_score_low",
        "normal_score_high",
    }

    missing = (
        required_keys
        - set(bundle.keys())
    )

    if missing:
        raise ValueError(
            "Invalid Isolation Forest model bundle. "
            f"Missing keys: {sorted(missing)}"
        )

    _MODEL = bundle["model"]
    _SCALER = bundle["scaler"]
    _FEATURE_NAMES = list(
        bundle["feature_names"]
    )
    _PROTOCOL_TO_ID = dict(
        bundle["protocol_to_id"]
    )

    _NORMAL_SCORE_LOW = float(
        bundle["normal_score_low"]
    )

    _NORMAL_SCORE_HIGH = float(
        bundle["normal_score_high"]
    )

    if (
        _NORMAL_SCORE_HIGH
        <= _NORMAL_SCORE_LOW
    ):
        raise ValueError(
            "Invalid calibrated normal-score range: "
            "normal_score_high must be greater than "
            "normal_score_low."
        )

    _INITIALIZED = True


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _ensure_initialized() -> None:
    if not _INITIALIZED:
        raise RuntimeError(
            "Isolation Forest is not initialized. "
            "Call initialize(model_path=...) first."
        )


# ---------------------------------------------------------------------------
# Protocol encoding
# ---------------------------------------------------------------------------

def _encode_protocol(
    protocol: str,
) -> float:
    """
    Convert a protocol string into the numeric value used during training.
    """

    normalized = (
        str(protocol)
        .strip()
        .upper()
    )

    if normalized not in _PROTOCOL_TO_ID:
        return float(
            _PROTOCOL_TO_ID.get(
                "UNKNOWN",
                -1,
            )
        )

    return float(
        _PROTOCOL_TO_ID[
            normalized
        ]
    )


# ---------------------------------------------------------------------------
# Feature vector
# ---------------------------------------------------------------------------

def _build_feature_vector(
    features: Dict[str, Any],
) -> np.ndarray:
    """
    Build the feature vector in EXACTLY the order stored in feature_names.
    """

    values = []

    for name in _FEATURE_NAMES:

        if name == "protocol_id":

            value = _encode_protocol(
                features.get(
                    "protocol",
                    "UNKNOWN",
                )
            )

        else:

            raw_value = features.get(
                name,
                0,
            )

            try:
                value = float(
                    raw_value
                )
            except (
                TypeError,
                ValueError,
            ):
                value = 0.0

        values.append(value)

    return np.asarray(
        [values],
        dtype=float,
    )


# ---------------------------------------------------------------------------
# Threat-score calibration
# ---------------------------------------------------------------------------

def _calibrate_threat_score(
    raw_decision_score: float,
) -> float:
    """
    Convert Isolation Forest decision_function() output into
    a continuous 0-100 threat score.

    Around the decision boundary:

        raw >= 0
            normal side

        raw < 0
            anomaly side

    More negative values indicate stronger anomalies.
    """

    if _MODEL is None:
        raise RuntimeError(
            "Isolation Forest model is not loaded."
        )

    if raw_decision_score >= 0:
        # Normal region.
        normal_reference = max(
            0.10,
            abs(
                float(
                    _NORMAL_SCORE_HIGH
                )
            ),
        )

        normalized = (
            raw_decision_score
            / normal_reference
        )

        normalized = max(
            0.0,
            min(
                1.0,
                normalized,
            ),
        )

        # Normal traffic occupies roughly 0-50.
        score = (
            50.0
            * (1.0 - normalized)
        )

    else:
        # Anomalous region.
        anomaly_reference = max(
            0.20,
            abs(
                float(
                    _NORMAL_SCORE_LOW
                )
            ),
        )

        normalized = (
            abs(raw_decision_score)
            / anomaly_reference
        )

        normalized = max(
            0.0,
            min(
                1.0,
                normalized,
            ),
        )

        # Anomalous traffic occupies roughly 50-100.
        score = (
            50.0
            + (
                normalized
                * 50.0
            )
        )

    return round(
        max(
            0.0,
            min(
                100.0,
                score,
            )
        ),
        2,
    )


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

def predict(
    features: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Predict whether a network flow is anomalous.

    Returns:

        {
            "anomaly_flag": bool,
            "threat_score": float,
            "raw_decision_score": float
        }
    """

    _ensure_initialized()

    X = _build_feature_vector(
        features
    )

    # ---------------------------------------------------------------
    # Apply training scaler.
    # ---------------------------------------------------------------

    X_scaled = _SCALER.transform(
        X
    )

    # ---------------------------------------------------------------
    # Binary Isolation Forest decision.
    #
    # -1 = anomaly
    # +1 = normal
    # ---------------------------------------------------------------

    prediction = int(
        _MODEL.predict(
            X_scaled
        )[0]
    )

    anomaly_flag = (
        prediction == -1
    )

    # ---------------------------------------------------------------
    # Raw continuous score.
    #
    # Larger = more normal
    # Smaller = more anomalous
    # ---------------------------------------------------------------

    raw_decision_score = float(
        _MODEL.decision_function(
            X_scaled
        )[0]
    )

    # ---------------------------------------------------------------
    # Calibrated 0-100 threat score.
    # ---------------------------------------------------------------

    threat_score = (
        _calibrate_threat_score(
            raw_decision_score
        )
    )

    return {
        "anomaly_flag":
            anomaly_flag,

        "threat_score":
            threat_score,

        "raw_decision_score":
            round(
                raw_decision_score,
                6,
            ),
    }