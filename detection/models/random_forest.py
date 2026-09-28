"""
Tuned Random Forest model with hyperparameter optimization.

Improvements over baseline:
- class_weight='balanced' to handle class imbalance
- RandomizedSearchCV for hyperparameter tuning
- Feature importance tracking
"""

import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import RandomizedSearchCV

logger = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).parent.parent / "data" / "models"

# Hyperparameter search space
RF_PARAM_DISTRIBUTIONS = {
    "n_estimators": [100, 200, 300],
    "max_depth": [10, 20, 30, None],
    "min_samples_split": [2, 5, 10],
    "min_samples_leaf": [1, 2, 4],
    "max_features": ["sqrt", "log2"],
    "class_weight": ["balanced", "balanced_subsample"],
}


class TunedRandomForest:
    """
    Hyperparameter-tuned Random Forest with class imbalance handling.
    """

    def __init__(self):
        self.model: RandomForestClassifier | None = None
        self.best_params: dict[str, Any] = {}
        self.name = "tuned_rf"

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        n_iter: int = 20,
        cv: int = 3,
        scoring: str = "f1_macro",
    ) -> dict[str, Any]:
        """
        Train with RandomizedSearchCV for hyperparameter optimization.

        Args:
            X_train: Training features.
            y_train: Training labels.
            n_iter: Number of parameter settings sampled.
            cv: Cross-validation folds.
            scoring: Scoring metric for CV.

        Returns:
            Dict with best_params and best_score.
        """
        logger.info(
            f"Training Tuned RF with RandomizedSearchCV "
            f"({n_iter} iterations, {cv}-fold CV, scoring={scoring})..."
        )

        base_model = RandomForestClassifier(random_state=42, n_jobs=-1)

        search = RandomizedSearchCV(
            estimator=base_model,
            param_distributions=RF_PARAM_DISTRIBUTIONS,
            n_iter=n_iter,
            cv=cv,
            scoring=scoring,
            random_state=42,
            n_jobs=-1,
            verbose=1,
        )

        search.fit(X_train, y_train)

        self.model = search.best_estimator_
        self.best_params = search.best_params_

        logger.info(f"Best params: {self.best_params}")
        logger.info(f"Best CV {scoring}: {search.best_score_:.4f}")

        return {
            "best_params": self.best_params,
            "best_score": search.best_score_,
        }

    def train_with_params(
        self, X_train: np.ndarray, y_train: np.ndarray, params: dict | None = None
    ) -> None:
        """Train with specific parameters (skip search)."""
        if params is None:
            params = {
                "n_estimators": 200,
                "max_depth": 20,
                "min_samples_split": 5,
                "min_samples_leaf": 2,
                "max_features": "sqrt",
                "class_weight": "balanced",
            }

        self.model = RandomForestClassifier(**params, random_state=42, n_jobs=-1)
        logger.info(f"Training RF with params: {params}")
        self.model.fit(X_train, y_train)
        self.best_params = params
        logger.info("Training complete.")

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict class labels."""
        if self.model is None:
            raise RuntimeError("Model not trained. Call train() first.")
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict class probabilities."""
        if self.model is None:
            raise RuntimeError("Model not trained. Call train() first.")
        return self.model.predict_proba(X)

    def get_feature_importance(self, feature_names: list) -> list:
        """Get feature importances sorted by importance."""
        if self.model is None:
            raise RuntimeError("Model not trained.")
        importances = self.model.feature_importances_
        indices = np.argsort(importances)[::-1]
        return [
            {"feature": feature_names[i], "importance": float(importances[i])}
            for i in indices
        ]

    def save(self, output_dir: Path | None = None) -> Path:
        """Save trained model and params."""
        if output_dir is None:
            output_dir = MODELS_DIR
        output_dir.mkdir(parents=True, exist_ok=True)
        filepath = output_dir / f"{self.name}.joblib"
        joblib.dump({"model": self.model, "params": self.best_params}, filepath)
        logger.info(f"Model saved to {filepath}")
        return filepath

    def load(self, input_dir: Path | None = None) -> None:
        """Load trained model and params."""
        if input_dir is None:
            input_dir = MODELS_DIR
        filepath = input_dir / f"{self.name}.joblib"
        data = joblib.load(filepath)
        self.model = data["model"]
        self.best_params = data["params"]
        logger.info(f"Model loaded from {filepath}")
