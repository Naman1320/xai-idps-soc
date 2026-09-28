"""
XGBoost classifier for intrusion detection.

Compared against Random Forest to select the best-performing model.
"""

import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.model_selection import RandomizedSearchCV
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

logger = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).parent.parent / "data" / "models"

# Hyperparameter search space
XGB_PARAM_DISTRIBUTIONS = {
    "n_estimators": [100, 200, 300],
    "max_depth": [4, 6, 8, 10],
    "learning_rate": [0.01, 0.05, 0.1, 0.2],
    "subsample": [0.7, 0.8, 0.9, 1.0],
    "colsample_bytree": [0.7, 0.8, 0.9, 1.0],
    "min_child_weight": [1, 3, 5],
    "gamma": [0, 0.1, 0.2],
}


class XGBoostModel:
    """
    XGBoost classifier with hyperparameter tuning and class imbalance handling.
    """

    def __init__(self):
        self.model: XGBClassifier | None = None
        self.best_params: dict[str, Any] = {}
        self.name = "xgboost"

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        n_iter: int = 20,
        cv: int = 3,
        scoring: str = "f1_macro",
    ) -> dict[str, Any]:
        """
        Train with RandomizedSearchCV.

        Args:
            X_train: Training features.
            y_train: Training labels (integer-encoded).
            n_iter: Number of parameter settings sampled.
            cv: Cross-validation folds.
            scoring: Scoring metric.

        Returns:
            Dict with best_params and best_score.
        """
        logger.info(
            f"Training XGBoost with RandomizedSearchCV "
            f"({n_iter} iterations, {cv}-fold CV)..."
        )

        n_classes = len(np.unique(y_train))

        base_model = XGBClassifier(
            objective="multi:softprob" if n_classes > 2 else "binary:logistic",
            num_class=n_classes if n_classes > 2 else None,
            random_state=42,
            n_jobs=-1,
            use_label_encoder=False,
            eval_metric="mlogloss" if n_classes > 2 else "logloss",
            tree_method="hist",  # Faster training, CPU-friendly
        )

        search = RandomizedSearchCV(
            estimator=base_model,
            param_distributions=XGB_PARAM_DISTRIBUTIONS,
            n_iter=n_iter,
            cv=cv,
            scoring=scoring,
            random_state=42,
            n_jobs=-1,
            verbose=1,
        )

        # Compute sample weights for class imbalance
        sample_weights = compute_sample_weight("balanced", y_train)
        search.fit(X_train, y_train, sample_weight=sample_weights)

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
        n_classes = len(np.unique(y_train))

        default_params = {
            "n_estimators": 200,
            "max_depth": 6,
            "learning_rate": 0.1,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "min_child_weight": 3,
            "gamma": 0.1,
        }
        if params:
            default_params.update(params)

        self.model = XGBClassifier(
            **default_params,
            objective="multi:softprob" if n_classes > 2 else "binary:logistic",
            random_state=42,
            n_jobs=-1,
            use_label_encoder=False,
            eval_metric="mlogloss" if n_classes > 2 else "logloss",
            tree_method="hist",
        )

        sample_weights = compute_sample_weight("balanced", y_train)
        logger.info(f"Training XGBoost with params: {default_params}")
        self.model.fit(X_train, y_train, sample_weight=sample_weights)
        self.best_params = default_params
        logger.info("Training complete.")

    def predict(self, X: np.ndarray) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("Model not trained.")
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("Model not trained.")
        return self.model.predict_proba(X)

    def get_feature_importance(self, feature_names: list) -> list:
        if self.model is None:
            raise RuntimeError("Model not trained.")
        importances = self.model.feature_importances_
        indices = np.argsort(importances)[::-1]
        return [
            {"feature": feature_names[i], "importance": float(importances[i])}
            for i in indices
        ]

    def save(self, output_dir: Path | None = None) -> Path:
        if output_dir is None:
            output_dir = MODELS_DIR
        output_dir.mkdir(parents=True, exist_ok=True)
        filepath = output_dir / f"{self.name}.joblib"
        joblib.dump({"model": self.model, "params": self.best_params}, filepath)
        logger.info(f"Model saved to {filepath}")
        return filepath

    def load(self, input_dir: Path | None = None) -> None:
        if input_dir is None:
            input_dir = MODELS_DIR
        filepath = input_dir / f"{self.name}.joblib"
        data = joblib.load(filepath)
        self.model = data["model"]
        self.best_params = data["params"]
        logger.info(f"Model loaded from {filepath}")
