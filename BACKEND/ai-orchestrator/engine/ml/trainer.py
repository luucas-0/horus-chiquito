"""Offline trainer for unified endpoint + network models."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class TrainingReport:
    """Summary of one training run."""

    ransomware_samples: int
    network_samples: int
    output_models: list[str]
    used_fallback: bool


class SecurityModelTrainer:
    """Train and export ML models for the unified security platform."""

    def __init__(self, dataset_dir: str | None = None, model_dir: str | None = None) -> None:
        base_ml_dir = Path(__file__).resolve().parent
        self.dataset_dir = Path(dataset_dir) if dataset_dir else base_ml_dir / "datasets"
        self.model_dir = Path(model_dir) if model_dir else base_ml_dir / "models"
        self.dataset_dir.mkdir(parents=True, exist_ok=True)
        self.model_dir.mkdir(parents=True, exist_ok=True)

    def prepare_ransomware_dataset(self) -> list[dict[str, Any]]:
        """Load endpoint/ransomware behavior rows for training."""

        dataset_file = self.dataset_dir / "ransomware_behaviors.csv"
        if not dataset_file.exists():
            return []

        return self._read_csv(dataset_file)

    def prepare_network_dataset(self) -> list[dict[str, Any]]:
        """Load network vulnerability rows for training."""

        dataset_file = self.dataset_dir / "network_vulnerabilities.csv"
        if not dataset_file.exists():
            return []

        return self._read_csv(dataset_file)

    def train_and_export(self) -> TrainingReport:
        """Train models and export artifacts.

        Fallback behavior:
        - If optional ML dependencies are missing, emit placeholder model metadata files.
        - This keeps inference operational through heuristic mode.
        """

        ransomware_data = self.prepare_ransomware_dataset()
        network_data = self.prepare_network_dataset()

        used_fallback = True
        output_models: list[str] = []

        try:
            import numpy as np  # type: ignore
            import xgboost as xgb  # type: ignore
            from sklearn.ensemble import IsolationForest, RandomForestClassifier  # type: ignore

            used_fallback = False

            endpoint_features, endpoint_labels = self._split_features_labels(ransomware_data, label_field="is_ransomware")
            network_features, network_labels = self._split_features_labels(network_data, label_field="risk_label")

            if endpoint_features and endpoint_labels:
                endpoint_array = np.array(endpoint_features, dtype=float)
                endpoint_labels_array = np.array(endpoint_labels, dtype=int)

                isolation = IsolationForest(random_state=42, contamination=0.08)
                isolation.fit(endpoint_array)

                random_forest = RandomForestClassifier(n_estimators=200, random_state=42)
                random_forest.fit(endpoint_array, endpoint_labels_array)

                endpoint_model_file = self.model_dir / "ransomware_behavior.meta.json"
                endpoint_model_file.write_text(
                    json.dumps({"type": "isolation_forest+random_forest", "samples": len(endpoint_features)}, indent=2),
                    encoding="utf-8",
                )
                output_models.append(str(endpoint_model_file))

            if network_features and network_labels:
                network_array = np.array(network_features, dtype=float)
                network_labels_array = np.array(network_labels, dtype=int)

                network_forest = RandomForestClassifier(n_estimators=200, random_state=42)
                network_forest.fit(network_array, network_labels_array)

                network_model_file = self.model_dir / "network_anomaly.meta.json"
                network_model_file.write_text(
                    json.dumps({"type": "random_forest", "samples": len(network_features)}, indent=2),
                    encoding="utf-8",
                )
                output_models.append(str(network_model_file))

            if endpoint_features and network_features:
                joined: list[list[float]] = []
                joined_labels: list[int] = []
                upper = min(len(endpoint_features), len(network_features))
                for index in range(upper):
                    joined.append(endpoint_features[index] + network_features[index])
                    joined_labels.append(max(endpoint_labels[index], network_labels[index]))

                booster = xgb.XGBRegressor(
                    n_estimators=200,
                    max_depth=4,
                    learning_rate=0.05,
                    subsample=0.9,
                    colsample_bytree=0.9,
                    random_state=42,
                )
                booster.fit(np.array(joined, dtype=float), np.array(joined_labels, dtype=float) * 100.0)

                unified_model_file = self.model_dir / "unified_risk_scorer.json"
                booster.save_model(str(unified_model_file))
                output_models.append(str(unified_model_file))

        except Exception:
            placeholder = self.model_dir / "fallback_models.json"
            placeholder.write_text(
                json.dumps(
                    {
                        "status": "fallback",
                        "reason": "optional_ml_dependencies_missing_or_training_failed",
                        "ransomware_samples": len(ransomware_data),
                        "network_samples": len(network_data),
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            output_models.append(str(placeholder))

        return TrainingReport(
            ransomware_samples=len(ransomware_data),
            network_samples=len(network_data),
            output_models=output_models,
            used_fallback=used_fallback,
        )

    def _read_csv(self, file_path: Path) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        header: list[str] = []

        for line_index, line in enumerate(file_path.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            parts = [part.strip() for part in line.split(",")]
            if line_index == 0:
                header = parts
                continue
            if not header:
                continue
            rows.append({header[i]: parts[i] if i < len(parts) else "" for i in range(len(header))})

        return rows

    def _split_features_labels(self, rows: list[dict[str, Any]], label_field: str) -> tuple[list[list[float]], list[int]]:
        features: list[list[float]] = []
        labels: list[int] = []

        for row in rows:
            if label_field not in row:
                continue

            vector: list[float] = []
            for key, value in row.items():
                if key == label_field:
                    continue
                try:
                    vector.append(float(value))
                except ValueError:
                    vector.append(1.0 if str(value).lower() in {"true", "yes", "critical", "high"} else 0.0)

            label_raw = str(row.get(label_field, "0")).lower()
            label = 1 if label_raw in {"1", "true", "critical", "high"} else 0

            features.append(vector)
            labels.append(label)

        return features, labels
