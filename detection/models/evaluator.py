"""
Model Evaluator: Comprehensive evaluation metrics for IDS classification.

Produces:
- Per-class Precision, Recall, F1-score
- Macro/weighted averaged metrics
- Confusion matrix
- False Positive Rate (FPR) per class
- PR-AUC (Precision-Recall Area Under Curve)
- Classification report as DataFrame
"""

import logging
from typing import Dict, Any, Optional, List

import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
    average_precision_score,
    roc_auc_score,
)
from sklearn.preprocessing import LabelBinarizer

logger = logging.getLogger(__name__)


class ModelEvaluator:
    """Compute and store comprehensive evaluation metrics."""

    def __init__(self, class_names: List[str]):
        """
        Args:
            class_names: List of class names (from LabelEncoder.classes_).
        """
        self.class_names = class_names
        self.results: Dict[str, Any] = {}

    def evaluate(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_proba: Optional[np.ndarray] = None,
        model_name: str = "model",
    ) -> Dict[str, Any]:
        """
        Run full evaluation suite.

        Args:
            y_true: True labels (integer-encoded).
            y_pred: Predicted labels (integer-encoded).
            y_proba: Predicted probabilities (n_samples × n_classes). Optional.
            model_name: Name for logging.

        Returns:
            Dict with all metrics.
        """
        logger.info(f"Evaluating {model_name}...")

        # Classification report
        report = classification_report(
            y_true, y_pred,
            target_names=self.class_names,
            output_dict=True,
            zero_division=0,
        )

        # Per-class metrics
        precision, recall, f1, support = precision_recall_fscore_support(
            y_true, y_pred, zero_division=0
        )

        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)

        # False Positive Rate per class
        fpr_per_class = self._compute_fpr_per_class(cm)

        # Overall FPR (benign traffic falsely flagged)
        # Assumes class 0 = Benign (verify with label_encoder)
        benign_idx = None
        for i, name in enumerate(self.class_names):
            if name.lower() in ("benign", "normal"):
                benign_idx = i
                break

        overall_fpr = None
        if benign_idx is not None:
            benign_total = cm[benign_idx].sum()
            benign_correct = cm[benign_idx, benign_idx]
            if benign_total > 0:
                overall_fpr = 1 - (benign_correct / benign_total)

        # PR-AUC (if probabilities available)
        pr_auc = None
        if y_proba is not None:
            try:
                lb = LabelBinarizer()
                y_true_bin = lb.fit_transform(y_true)
                if y_true_bin.shape[1] == 1:
                    # Binary case
                    pr_auc = float(average_precision_score(y_true_bin, y_proba[:, 1]))
                else:
                    pr_auc = float(
                        average_precision_score(y_true_bin, y_proba, average="macro")
                    )
            except Exception as e:
                logger.warning(f"PR-AUC computation failed: {e}")

        results = {
            "model_name": model_name,
            "classification_report": report,
            "per_class": {
                self.class_names[i]: {
                    "precision": float(precision[i]),
                    "recall": float(recall[i]),
                    "f1_score": float(f1[i]),
                    "support": int(support[i]),
                    "fpr": fpr_per_class.get(i, None),
                }
                for i in range(len(self.class_names))
            },
            "macro_f1": float(report["macro avg"]["f1-score"]),
            "weighted_f1": float(report["weighted avg"]["f1-score"]),
            "overall_fpr": overall_fpr,
            "pr_auc": pr_auc,
            "confusion_matrix": cm.tolist(),
        }

        self.results[model_name] = results

        # Log summary
        logger.info(f"  Macro F1: {results['macro_f1']:.4f}")
        logger.info(f"  Weighted F1: {results['weighted_f1']:.4f}")
        if overall_fpr is not None:
            logger.info(f"  Overall FPR: {overall_fpr:.4f}")
        if pr_auc is not None:
            logger.info(f"  PR-AUC (macro): {pr_auc:.4f}")

        return results

    def _compute_fpr_per_class(self, cm: np.ndarray) -> Dict[int, float]:
        """Compute FPR for each class from confusion matrix."""
        n_classes = cm.shape[0]
        fpr = {}
        for i in range(n_classes):
            # FP for class i = sum of column i minus the diagonal
            fp = cm[:, i].sum() - cm[i, i]
            # TN for class i = total - (TP + FP + FN)
            tn = cm.sum() - cm[i, :].sum() - cm[:, i].sum() + cm[i, i]
            if (fp + tn) > 0:
                fpr[i] = float(fp / (fp + tn))
            else:
                fpr[i] = 0.0
        return fpr

    def get_report_dataframe(self, model_name: str) -> pd.DataFrame:
        """Get per-class metrics as a pandas DataFrame for display."""
        if model_name not in self.results:
            raise KeyError(f"No results for model '{model_name}'")

        per_class = self.results[model_name]["per_class"]
        rows = []
        for class_name, metrics in per_class.items():
            rows.append({
                "Class": class_name,
                "Precision": f"{metrics['precision']:.4f}",
                "Recall": f"{metrics['recall']:.4f}",
                "F1-Score": f"{metrics['f1_score']:.4f}",
                "FPR": f"{metrics['fpr']:.4f}" if metrics['fpr'] is not None else "N/A",
                "Support": metrics["support"],
            })

        return pd.DataFrame(rows)

    def compare_models(self) -> pd.DataFrame:
        """Compare all evaluated models side by side."""
        rows = []
        for name, res in self.results.items():
            rows.append({
                "Model": name,
                "Macro F1": f"{res['macro_f1']:.4f}",
                "Weighted F1": f"{res['weighted_f1']:.4f}",
                "Overall FPR": f"{res['overall_fpr']:.4f}" if res['overall_fpr'] is not None else "N/A",
                "PR-AUC": f"{res['pr_auc']:.4f}" if res['pr_auc'] is not None else "N/A",
            })
        return pd.DataFrame(rows)
