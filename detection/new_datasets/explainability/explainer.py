"""
XAI Explainability Module for new IoT / NetFlow datasets.

Provides:
  1. SHAP TreeExplainer (global + local) for tree-based models
  2. LIME tabular explanations
  3. explain_alert() – plain-English alert explanation for SOC analysts

The explain_alert function outputs:
  - Predicted class and confidence
  - Severity level
  - Top 5 contributing features in analyst-friendly language
"""

import logging
from typing import Dict, Any, List, Optional, Tuple

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


# ── Feature name → human-friendly description ────────────────────────────────
FEATURE_DESCRIPTIONS = {
    "flow_duration":       "total duration of the network flow",
    "total_fwd_packets":   "number of packets sent by the source",
    "total_bwd_packets":   "number of packets sent by the destination",
    "total_fwd_bytes":     "total bytes sent by the source",
    "total_bwd_bytes":     "total bytes sent by the destination",
    "fwd_packet_length_mean": "average size of source packets",
    "bwd_packet_length_mean": "average size of destination packets",
    "flow_bytes/s":        "data transfer rate (bytes per second)",
    "flow_packets/s":      "packet rate (packets per second)",
    "syn_flag_count":      "number of SYN flags (connection initiation)",
    "ack_flag_count":      "number of ACK flags",
    "fin_flag_count":      "number of FIN flags (connection teardown)",
    "rst_flag_count":      "number of RST flags (connection reset)",
    "psh_flag_count":      "number of PSH flags (data push)",
    "protocol":            "transport protocol used",
    "in_bytes":            "incoming byte volume",
    "out_bytes":           "outgoing byte volume",
    "in_pkts":             "incoming packet count",
    "out_pkts":            "outgoing packet count",
}


def compute_shap_global(
    model,
    X_sample: np.ndarray,
    feature_names: List[str],
    dataset_name: str,
    max_samples: int = 500,
) -> Dict[str, Any]:
    """
    Compute global SHAP values using TreeExplainer.

    Returns:
        Dict with shap_values, expected_value, and top global features.
    """
    import shap

    logger.info(f"[{dataset_name}] Computing global SHAP values...")

    if X_sample.shape[0] > max_samples:
        idx = np.random.RandomState(42).choice(
            X_sample.shape[0], max_samples, replace=False
        )
        X_sample = X_sample[idx]

    try:
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X_sample)
    except Exception as e:
        logger.warning(f"  TreeExplainer failed ({e}), trying KernelExplainer...")
        bg = shap.kmeans(X_sample, 50)
        explainer = shap.KernelExplainer(model.predict_proba, bg)
        shap_values = explainer.shap_values(X_sample, nsamples=100)

    # Global importance: mean absolute SHAP per feature
    if isinstance(shap_values, list):
        # Multi-class: average across classes
        abs_vals = np.mean([np.abs(sv) for sv in shap_values], axis=0)
    else:
        abs_vals = np.abs(shap_values)

    mean_importance = abs_vals.mean(axis=0)
    top_idx = np.argsort(mean_importance)[::-1][:10]
    top_features = [(feature_names[i], float(mean_importance[i])) for i in top_idx]

    logger.info(f"  Top 10 global SHAP features:")
    for fname, imp in top_features:
        logger.info(f"    {fname}: {imp:.4f}")

    return {
        "shap_values": shap_values,
        "expected_value": explainer.expected_value,
        "top_global_features": top_features,
        "feature_names": feature_names,
    }


def compute_lime_explanation(
    model,
    X_instance: np.ndarray,
    X_train: np.ndarray,
    feature_names: List[str],
    class_names: List[str],
) -> Dict[str, Any]:
    """
    Compute LIME explanation for a single instance.

    Returns:
        Dict with top features and their contributions.
    """
    from lime.lime_tabular import LimeTabularExplainer

    explainer = LimeTabularExplainer(
        X_train,
        feature_names=feature_names,
        class_names=class_names,
        mode="classification",
        random_state=42,
    )

    exp = explainer.explain_instance(
        X_instance,
        model.predict_proba,
        num_features=10,
    )

    explanation = {
        "prediction": exp.predict_proba if hasattr(exp, "predict_proba") else None,
        "features": [],
    }
    for feat, weight in exp.as_list():
        explanation["features"].append({
            "feature": feat,
            "weight": weight,
            "direction": "attack" if weight > 0 else "benign",
        })

    return explanation


def explain_alert(
    model,
    X_instance: np.ndarray,
    feature_names: List[str],
    label_encoder,
    dataset_name: str = "",
) -> Dict[str, Any]:
    """
    Generate a plain-English SOC analyst explanation for a single alert.

    Returns:
        Dict with predicted_class, confidence, severity, and top 5
        feature explanations in human-readable language.
    """
    import shap

    # Predict
    proba = model.predict_proba(X_instance.reshape(1, -1))[0]
    pred_idx = np.argmax(proba)
    pred_class = label_encoder.inverse_transform([pred_idx])[0]
    confidence = float(proba[pred_idx])

    # Severity
    if confidence >= 0.90:
        severity = "CRITICAL"
    elif confidence >= 0.75:
        severity = "HIGH"
    elif confidence >= 0.50:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # SHAP local explanation
    try:
        explainer = shap.TreeExplainer(model)
        sv = explainer.shap_values(X_instance.reshape(1, -1))
        if isinstance(sv, list):
            # Use the SHAP values for the predicted class
            shap_for_class = sv[pred_idx][0]
        else:
            shap_for_class = sv[0]
    except Exception:
        shap_for_class = np.zeros(len(feature_names))

    # Top 5 features by absolute SHAP
    top_idx = np.argsort(np.abs(shap_for_class))[::-1][:5]

    explanations = []
    for i in top_idx:
        fname = feature_names[i]
        sval = float(shap_for_class[i])
        fval = float(X_instance[i])
        direction = "pushed toward ATTACK" if sval > 0 else "pushed toward BENIGN"

        # Human-friendly description
        human_name = FEATURE_DESCRIPTIONS.get(
            fname.lower(), fname.replace("_", " ")
        )

        explanations.append({
            "feature": fname,
            "human_name": human_name,
            "observed_value": fval,
            "shap_value": sval,
            "direction": direction,
            "summary": (
                f"The {human_name} (value: {fval:.2f}) "
                f"{direction} (SHAP: {sval:+.4f})"
            ),
        })

    result = {
        "dataset": dataset_name,
        "predicted_class": pred_class,
        "confidence": confidence,
        "severity": severity,
        "class_probabilities": {
            label_encoder.inverse_transform([i])[0]: float(p)
            for i, p in enumerate(proba)
        },
        "top_features": explanations,
        "plain_english": (
            f"🚨 Alert Classification: {pred_class} "
            f"(Confidence: {confidence:.1%}, Severity: {severity})\n"
            f"{'─'*50}\n"
            + "\n".join(
                f"  {i+1}. {e['summary']}"
                for i, e in enumerate(explanations)
            )
        ),
    }

    return result
