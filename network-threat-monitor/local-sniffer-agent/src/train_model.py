"""
train_model.py

Train Isolation Forest using flow-level features.

Feature vector:

0  packet_count
1  total_bytes
2  average_packet_size
3  packets_per_second
4  bytes_per_second
5  src_port
6  dst_port
7  unique_destinations
8  unique_destination_ports
9  protocol_id
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

import joblib
import numpy as np
import yaml
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger(__name__)


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


FEATURE_NAMES = [
    "packet_count",
    "total_bytes",
    "average_packet_size",
    "packets_per_second",
    "bytes_per_second",
    "src_port",
    "dst_port",
    "unique_destinations",
    "unique_destination_ports",
    "protocol_id",
]


def load_config(path: str) -> dict:
    with open(
        path,
        "r",
        encoding="utf-8",
    ) as file:
        return yaml.safe_load(file)


def generate_synthetic_normal_data(
    samples: int = 10000,
    random_state: int = 42,
) -> np.ndarray:
    """
    Generate approximate normal flow behavior.
    """

    rng = np.random.default_rng(
        random_state
    )

    packet_count = np.clip(
        rng.normal(18, 7, samples),
        1,
        60,
    )

    average_packet_size = np.clip(
        rng.normal(650, 180, samples),
        60,
        1500,
    )

    total_bytes = (
        packet_count
        * average_packet_size
    )

    packets_per_second = np.clip(
        rng.normal(3.5, 1.2, samples),
        0.2,
        10,
    )

    bytes_per_second = (
        packets_per_second
        * average_packet_size
    )

    src_port = rng.integers(
        1024,
        65535,
        samples,
    )

    dst_port = rng.choice(
        [
            53,
            80,
            443,
            443,
            443,
            22,
        ],
        samples,
    )

    unique_destinations = np.clip(
        rng.poisson(2, samples) + 1,
        1,
        10,
    )

    unique_destination_ports = np.clip(
        rng.poisson(1, samples) + 1,
        1,
        6,
    )

    protocol_id = rng.choice(
        [
            1,
            1,
            1,
            1,
            2,
            6,
        ],
        samples,
    )

    return np.column_stack(
        [
            packet_count,
            total_bytes,
            average_packet_size,
            packets_per_second,
            bytes_per_second,
            src_port,
            dst_port,
            unique_destinations,
            unique_destination_ports,
            protocol_id,
        ]
    ).astype(float)


def train_model(
    data: np.ndarray,
    model_path: str,
    contamination: float,
    n_estimators: int,
    random_state: int,
) -> None:

    logger.info(
        "Training data shape: %s",
        data.shape,
    )

    scaler = StandardScaler()

    scaled = scaler.fit_transform(data)

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )

    model.fit(scaled)

    normal_scores = (
        model.decision_function(scaled)
    )

    score_low = float(
        np.percentile(
            normal_scores,
            1,
        )
    )

    score_high = float(
        np.percentile(
            normal_scores,
            99,
        )
    )

    bundle = {
        "model": model,
        "scaler": scaler,
        "feature_names": FEATURE_NAMES,
        "protocol_to_id": PROTOCOL_TO_ID,
        "normal_score_low": score_low,
        "normal_score_high": score_high,
    }

    target = Path(model_path)

    target.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(
        bundle,
        target,
    )

    logger.info(
        "Model saved to %s",
        target,
    )


def main() -> None:

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--config",
        default="config.yaml",
    )

    args = parser.parse_args()

    config = load_config(
        args.config
    )

    model_config = config["model"]

    data = (
        generate_synthetic_normal_data()
    )

    train_model(
        data=data,
        model_path=model_config["path"],
        contamination=model_config["contamination"],
        n_estimators=model_config["n_estimators"],
        random_state=model_config["random_state"],
    )


if __name__ == "__main__":
    main()