"""
Baseline Model: Default Random Forest with no hyperparameter tuning.

This serves as the comparison baseline for the evaluation.
Per Section S of the project definition: "Default scikit-learn Random Forest
(100 trees, no hyperparameter tuning, class_weight=None, all features)"
"""

import logging
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

logger = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).parent.parent / "data" / "models"


class BaselineModel:
    """
    Default Random Forest baseline — sklearn defaults, no tuning.

    Used to establish what "better" means for the tuned models.
    """

    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
            # NOTE: class_weight=None (default) — intentionally unweighted
            # for baseline. The tuned model will use class_weight='balanced'.
        )
        self.name = "baseline_rf"

    def train(self, X_train: np.ndarray, y_train: np.ndarray) -> None:
        """Train baseline model."""
        logger.info(
            f"Training baseline Random Forest ({X_train.shape[0]} samples, {X_train.shape[1]} features)..."
        )
        self.model.fit(X_train, y_train)
        logger.info("Baseline training complete.")

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict class labels."""
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict class probabilities."""
        return self.model.predict_proba(X)

    def save(self, output_dir: Path | None = None) -> Path:
        """Save trained model."""
        if output_dir is None:
            output_dir = MODELS_DIR
        output_dir.mkdir(parents=True, exist_ok=True)
        filepath = output_dir / f"{self.name}.joblib"
        joblib.dump(self.model, filepath)
        logger.info(f"Model saved to {filepath}")
        return filepath

    def load(self, input_dir: Path | None = None) -> None:
        """Load trained model."""
        if input_dir is None:
            input_dir = MODELS_DIR
        filepath = input_dir / f"{self.name}.joblib"
        self.model = joblib.load(filepath)
        logger.info(f"Model loaded from {filepath}")
