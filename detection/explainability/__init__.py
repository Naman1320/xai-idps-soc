"""
SHAP Explainability Layer.

Provides per-alert SHAP explanations for tree-based models.
This is the core of what makes the detection pipeline "explainable" —
and carrying these explanations to the dashboard is the project's
central contribution.
"""

import logging
from typing import Any, Dict, List, Optional

import numpy as np
import shap

logger = logging.getLogger(__name__)


class ShapExplainer:
    """
    Wrapper around SHAP TreeExplainer for per-alert explanations.

    Computes SHAP values for each prediction and serializes them
    into a JSON-friendly format for the SOC backend.
    """

    def __init__(self, model, feature_names: list[str]):
        """
        Args:
            model: A fitted tree-based model (RF, XGBoost, LightGBM).
            feature_names: List of feature names matching training data columns.
        """
        self.feature_names = feature_names
        self.explainer = shap.TreeExplainer(model)
        logger.info(f"SHAP TreeExplainer initialized for {type(model).__name__}")

    def explain_single(
        self,
        X_single: np.ndarray,
        predicted_class_idx: int,
        top_n: int = 10,
    ) -> dict[str, Any]:
        """
        Generate SHAP explanation for a single prediction.

        Args:
            X_single: Feature vector for one sample (1D array or 2D with shape (1, n_features)).
            predicted_class_idx: Index of the predicted class.
            top_n: Number of top contributing features to include.

        Returns:
            Dict with base_value, feature_contributions (sorted by abs SHAP value),
            and prediction_value.
        """
        if X_single.ndim == 1:
            X_single = X_single.reshape(1, -1)

        shap_values = self.explainer.shap_values(X_single)

        # Handle different SHAP output formats:
        # - For multi-class RF: list of arrays, one per class
        # - For XGBoost multi-class: 3D array (n_samples, n_features, n_classes)
        if isinstance(shap_values, list):
            # Multi-class RF: list of (n_samples, n_features) arrays
            class_shap = shap_values[predicted_class_idx][0]
            base_value = self.explainer.expected_value[predicted_class_idx]
        elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
            # XGBoost: (n_samples, n_features, n_classes)
            class_shap = shap_values[0, :, predicted_class_idx]
            base_value = float(self.explainer.expected_value[predicted_class_idx])
        elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 2:
            # Binary or single output
            class_shap = shap_values[0]
            base_value = float(
                self.explainer.expected_value
                if isinstance(self.explainer.expected_value, (int, float))
                else self.explainer.expected_value[0]
            )
        else:
            raise ValueError(f"Unexpected SHAP values format: type={type(shap_values)}")

        # Build feature contributions sorted by absolute SHAP value
        contributions = []
        sorted_indices = np.argsort(np.abs(class_shap))[::-1]

        for idx in sorted_indices[:top_n]:
            contributions.append(
                {
                    "feature": self.feature_names[idx],
                    "shap_value": float(class_shap[idx]),
                    "feature_value": float(X_single[0, idx]),
                    "rank": len(contributions) + 1,
                }
            )

        return {
            "base_value": float(base_value),
            "feature_contributions": contributions,
            "prediction_value": float(base_value + class_shap.sum()),
        }

    def explain_batch(
        self,
        X_batch: np.ndarray,
        predicted_class_indices: np.ndarray,
        top_n: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Generate SHAP explanations for a batch of predictions.

        Args:
            X_batch: Feature matrix (n_samples, n_features).
            predicted_class_indices: Predicted class index for each sample.
            top_n: Top features per explanation.

        Returns:
            List of explanation dicts.
        """
        explanations = []
        for i in range(len(X_batch)):
            exp = self.explain_single(
                X_batch[i], int(predicted_class_indices[i]), top_n=top_n
            )
            explanations.append(exp)

        logger.info(f"Generated {len(explanations)} SHAP explanations")
        return explanations
