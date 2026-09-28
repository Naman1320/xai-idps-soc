"""
Evaluation Module for new IoT / NetFlow datasets.

Metrics reported per model per dataset:
  - Accuracy
  - Precision (macro & weighted)
  - Recall    (macro & weighted)
  - F1-score  (macro & weighted)
  - ROC-AUC   (OvR, weighted)
  - False Positive Rate
  - Confusion Matrix
  - Per-class classification report

Also provides a combined comparison table across all datasets.
"""

import logging
from typing import Dict, Any, List, Optional

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)

logger = logging.getLogger(__name__)


def evaluate_model(
    model,
    X_test: np.ndarray,
    y_test: np.ndarray,
    dataset_name: str,
    model_name: str,
    label_encoder=None,
) -> Dict[str, Any]:
    """
    Full evaluation of a single model on a test set.

    Returns:
        Dict with all metrics, confusion matrix, and classification report.
    """
    y_pred = model.predict(X_test)

    # Probabilities for ROC-AUC
    try:
        y_proba = model.predict_proba(X_test)
    except Exception:
        y_proba = None

    metrics = {
        "dataset": dataset_name,
        "model": model_name,
        "accuracy": accuracy_score(y_test, y_pred),
        "precision_macro": precision_score(y_test, y_pred, average="macro", zero_division=0),
        "precision_weighted": precision_score(y_test, y_pred, average="weighted", zero_division=0),
        "recall_macro": recall_score(y_test, y_pred, average="macro", zero_division=0),
        "recall_weighted": recall_score(y_test, y_pred, average="weighted", zero_division=0),
        "f1_macro": f1_score(y_test, y_pred, average="macro", zero_division=0),
        "f1_weighted": f1_score(y_test, y_pred, average="weighted", zero_division=0),
    }

    # ROC-AUC
    if y_proba is not None:
        try:
            n_classes = len(np.unique(y_test))
            if n_classes == 2:
                metrics["roc_auc"] = roc_auc_score(y_test, y_proba[:, 1])
            else:
                metrics["roc_auc"] = roc_auc_score(
                    y_test, y_proba, multi_class="ovr", average="weighted"
                )
        except Exception as e:
            logger.warning(f"  ROC-AUC computation failed: {e}")
            metrics["roc_auc"] = None
    else:
        metrics["roc_auc"] = None

    # False Positive Rate (binary: attack vs benign)
    cm = confusion_matrix(y_test, y_pred)
    metrics["confusion_matrix"] = cm

    # FPR: sum of off-diagonal in benign row / total benign
    if label_encoder is not None:
        classes = label_encoder.classes_
    else:
        classes = sorted(np.unique(np.concatenate([y_test, y_pred])))

    benign_idx = None
    for i, c in enumerate(classes):
        if str(c).lower() in ("benign", "0", "normal"):
            benign_idx = i
            break

    if benign_idx is not None and benign_idx < cm.shape[0]:
        total_benign = cm[benign_idx].sum()
        if total_benign > 0:
            fp = total_benign - cm[benign_idx, benign_idx]
            metrics["fpr"] = fp / total_benign
        else:
            metrics["fpr"] = 0.0
    else:
        metrics["fpr"] = None

    # Classification report
    if label_encoder is not None:
        target_names = [str(c) for c in label_encoder.classes_]
    else:
        target_names = None

    report = classification_report(
        y_test, y_pred,
        target_names=target_names,
        zero_division=0,
        output_dict=True,
    )
    metrics["classification_report"] = report

    # Log summary
    logger.info(
        f"[{dataset_name} / {model_name}]  "
        f"Acc={metrics['accuracy']:.4f}  "
        f"F1m={metrics['f1_macro']:.4f}  "
        f"F1w={metrics['f1_weighted']:.4f}  "
        f"AUC={metrics.get('roc_auc', 'N/A')}  "
        f"FPR={metrics.get('fpr', 'N/A')}"
    )

    return metrics


def evaluate_all_models(
    models: Dict[str, Any],
    X_test: np.ndarray,
    y_test: np.ndarray,
    dataset_name: str,
    label_encoder=None,
) -> List[Dict[str, Any]]:
    """Evaluate multiple models and return list of result dicts."""
    results = []
    for model_name, model in models.items():
        r = evaluate_model(
            model, X_test, y_test,
            dataset_name, model_name, label_encoder
        )
        results.append(r)
    return results


def build_comparison_table(
    all_results: List[Dict[str, Any]],
) -> pd.DataFrame:
    """
    Build a comparison table across all datasets and models.
    Suitable for printing or exporting.
    """
    rows = []
    for r in all_results:
        rows.append({
            "Dataset": r["dataset"],
            "Model": r["model"],
            "Accuracy": f"{r['accuracy']:.4f}",
            "F1 (Macro)": f"{r['f1_macro']:.4f}",
            "F1 (Weighted)": f"{r['f1_weighted']:.4f}",
            "Precision (M)": f"{r['precision_macro']:.4f}",
            "Recall (M)": f"{r['recall_macro']:.4f}",
            "ROC-AUC": f"{r['roc_auc']:.4f}" if r.get("roc_auc") else "N/A",
            "FPR": f"{r['fpr']:.4f}" if r.get("fpr") is not None else "N/A",
        })
    return pd.DataFrame(rows)


def print_confusion_matrix(
    cm: np.ndarray,
    class_names: List[str],
    dataset_name: str,
    model_name: str,
) -> str:
    """Format confusion matrix for logging."""
    header = f"\n{'='*60}\nConfusion Matrix: {dataset_name} / {model_name}\n{'='*60}"
    df = pd.DataFrame(cm, index=class_names, columns=class_names)
    return f"{header}\n{df.to_string()}\n"
