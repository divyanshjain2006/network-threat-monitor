"""
train_model.py

Train the Isolation Forest model used by the local edge agent.

The model is unsupervised:
    - Training data represents NORMAL network traffic.
    - Isolation Forest learns what normal observations look like.
    - Unusual observations become anomalies during inference.

Feature vector:

    [
        packet_size,
        protocol_id,
        src_port,
        dst_port
    ]

protocol_id mapping:

    TCP   = 1
    UDP   = 2
    ICMP  = 3
    HTTP  = 4
    HTTPS = 5
    DNS   = 6
    TLS   = 7
    UNKNOWN = 0
"""

from __future__ import annotations

import argparse
import csv
import logging
import os
from pathlib import Path
from typing import List

import joblib
import numpy as np
import yaml
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Protocol mapping
# ---------------------------------------------------------------------------

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
# Configuration
# ---------------------------------------------------------------------------

def load_config(config_path: str) -> dict:
    """Load YAML configuration."""

    with open(config_path, "r", encoding="utf-8") as file:
        return yaml.safe_load(file)


# ---------------------------------------------------------------------------
# CSV loading
# ---------------------------------------------------------------------------

def load_training_csv(csv_path: str) -> np.ndarray:
    """
    Load normal traffic features from CSV.

    Expected columns:

        packet_size,protocol_id,src_port,dst_port

    Example:

        packet_size,protocol_id,src_port,dst_port
        512,1,49152,443
        1024,1,49153,443
        128,2,53000,53
    """

    rows: List[List[float]] = []

    with open(csv_path, "r", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        required_columns = {
            "packet_size",
            "protocol_id",
            "src_port",
            "dst_port",
        }

        if not required_columns.issubset(reader.fieldnames or []):
            raise ValueError(
                "Training CSV must contain columns: "
                "packet_size, protocol_id, src_port, dst_port"
            )

        for row in reader:
            rows.append(
                [
                    float(row["packet_size"]),
                    float(row["protocol_id"]),
                    float(row["src_port"]),
                    float(row["dst_port"]),
                ]
            )

    if not rows:
        raise ValueError("Training CSV contains no data.")

    return np.asarray(rows, dtype=np.float64)


# ---------------------------------------------------------------------------
# Synthetic fallback
# ---------------------------------------------------------------------------

def generate_synthetic_normal_data(
    samples: int = 5000,
    random_state: int = 42,
) -> np.ndarray:
    """
    Generate approximate NORMAL network traffic.

    This is ONLY useful for demonstrating that the ML pipeline works.

    For a serious deployment, replace this with traffic captured from
    your actual environment.
    """

    rng = np.random.default_rng(random_state)

    # Common packet sizes.
    packet_size = rng.normal(
        loc=750,
        scale=300,
        size=samples,
    )

    packet_size = np.clip(packet_size, 40, 1500)

    # Mostly TCP / HTTPS-style traffic.
    protocol_choices = np.array(
        [1, 1, 1, 1, 2, 6]
    )

    protocol_id = rng.choice(
        protocol_choices,
        size=samples,
    )

    # Ephemeral client ports.
    src_port = rng.integers(
        low=1024,
        high=65535,
        size=samples,
    )

    # Common destination ports.
    dst_port_choices = np.array(
        [
            53,
            80,
            443,
            443,
            443,
            22,
            123,
        ]
    )

    dst_port = rng.choice(
        dst_port_choices,
        size=samples,
    )

    return np.column_stack(
        [
            packet_size,
            protocol_id,
            src_port,
            dst_port,
        ]
    ).astype(np.float64)


# ---------------------------------------------------------------------------
# Model training
# ---------------------------------------------------------------------------

def train_model(
    training_data: np.ndarray,
    model_path: str,
    contamination: float,
    n_estimators: int,
    random_state: int,
) -> None:
    """
    Train and save an Isolation Forest pipeline.

    StandardScaler is used before Isolation Forest because the raw feature
    magnitudes differ significantly:

        packet_size -> ~40-1500
        ports       -> ~0-65535
        protocol_id -> 0-7

    Scaling gives each feature a more balanced numerical representation.
    """

    logger.info(
        "Training data shape: %s",
        training_data.shape,
    )

    scaler = StandardScaler()

    scaled_features = scaler.fit_transform(training_data)

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )

    model.fit(scaled_features)

    model_bundle = {
        "model": model,
        "scaler": scaler,
        "feature_names": [
            "packet_size",
            "protocol_id",
            "src_port",
            "dst_port",
        ],
        "protocol_to_id": PROTOCOL_TO_ID,
    }

    model_file = Path(model_path)

    model_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(
        model_bundle,
        model_file,
    )

    logger.info(
        "Model saved to %s",
        model_file,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train Zero-Trust Isolation Forest model."
    )

    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to config.yaml",
    )

    parser.add_argument(
        "--csv",
        default=None,
        help="Optional CSV containing normal network traffic.",
    )

    args = parser.parse_args()

    config = load_config(args.config)

    model_config = config["model"]

    if args.csv:
        logger.info(
            "Loading training data from %s",
            args.csv,
        )

        training_data = load_training_csv(args.csv)

    else:
        logger.warning(
            "No training CSV supplied. "
            "Using synthetic normal traffic."
        )

        training_data = generate_synthetic_normal_data()

    train_model(
        training_data=training_data,
        model_path=model_config["path"],
        contamination=model_config["contamination"],
        n_estimators=model_config["n_estimators"],
        random_state=model_config["random_state"],
    )


if __name__ == "__main__":
    main()