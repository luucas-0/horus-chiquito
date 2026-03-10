"""Entrypoint for running offline ML training container."""

from __future__ import annotations

from dataclasses import asdict
import json

from engine.ml.trainer import SecurityModelTrainer


def main() -> None:
    trainer = SecurityModelTrainer()
    report = trainer.train_and_export()
    print(json.dumps(asdict(report), indent=2))


if __name__ == "__main__":
    main()
