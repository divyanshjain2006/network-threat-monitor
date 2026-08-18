"""
train_model.py

Train the Isolation Forest model for the Zero-Trust edge agent.

Feature vector:

    packet_size
    protocol_id
    src_port
    dst_port
"""

from __future__ import annotations

import argparse
import csv
import logging
from pathlib import Path
from typing import List

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


def load_config(config_path: str) -> dict:
    with open(
        config_path,
        "r",
        encoding="utf-8",
    ) as file:
        return yaml.safe_load(file)


def load_training_csv(
    csv_path: str,
) -> np.ndarray:
    """
    Expected columns:

        packet_size,
        protocol_id,
        src_port,
        dst_port
    """

    rows: List[List[float]] = []

    with open(
        csv_path,
        "r",
        encoding="utf-8",
    ) as file:

        reader = csv.DictReader(file)

        required = {
            "packet_size",
            "protocol_id",
            "src_port",
            "dst_port",
        }

        if not required.issubset(
            reader.fieldnames or []
        ):
            raise ValueError(
                "Training CSV must contain: "
                "packet_size, protocol_id, "
                "src_port, dst_port"
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
        raise ValueError(
            "Training CSV contains no rows."
        )

    return np.asarray(
        rows,
        dtype=np.float64,
    )


def generate_synthetic_normal_data(
    samples: int = 10000,
    random_state: int = 42,
) -> np.ndarray:
    """
    Generate NORMAL network traffic.

    The resulting distribution intentionally represents common
    desktop/application traffic.
    """

    rng = np.random.default_rng(
        random_state
    )

    packet_size = np.clip(
        rng.normal(
            loc=700,
            scale=220,
            size=samples,
        ),
        60,
        1500,
    )

    protocol_id = rng.choice(
        [
            1, 1, 1, 1, 2, 6
        ],
        size=samples,
    )

    src_port = rng.integers(
        1024,
        65535,
        size=samples,
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


def train_model(
    training_data: np.ndarray,
    model_path: str,
    contamination: float,
    n_estimators: int,
    random_state: int,
) -> None:

    logger.info(
        "Training data shape: %s",
        training_data.shape,
    )

    scaler = StandardScaler()

    scaled_data = scaler.fit_transform(
        training_data
    )

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )

    model.fit(scaled_data)

    # ------------------------------------------------------------------
    # Calibrate threat-score boundaries.
    #
    # decision_function():
    #     higher = more normal
    #     lower  = more anomalous
    #
    # We save the normal distribution so inference can convert a score
    # into a meaningful 0-100 range.
    # ------------------------------------------------------------------

    normal_scores = model.decision_function(
        scaled_data
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
        "normal_score_low": score_low,
        "normal_score_high": score_high,
    }

    model_file = Path(
        model_path
    )

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

    logger.info(
        "Normal score range: %.5f → %.5f",
        score_low,
        score_high,
    )


def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "Train the Zero-Trust "
            "Isolation Forest model."
        )
    )

    parser.add_argument(
        "--config",
        default="config.yaml",
    )

    parser.add_argument(
        "--csv",
        default=None,
    )

    args = parser.parse_args()

    config = load_config(
        args.config
    )

    model_config = config["model"]

    if args.csv:
        logger.info(
            "Using CSV training data: %s",
            args.csv,
        )

        training_data = load_training_csv(
            args.csv
        )

    else:
        logger.warning(
            "No CSV supplied."
        )

        logger.warning(
            "Using synthetic normal traffic."
        )

        training_data = (
            generate_synthetic_normal_data()
        )

    train_model(
        training_data=training_data,
        model_path=model_config["path"],
        contamination=model_config[
            "contamination"
        ],
        n_estimators=model_config[
            "n_estimators"
        ],
        random_state=model_config[
            "random_state"
        ],
    )


if __name__ == "__main__":
    main()