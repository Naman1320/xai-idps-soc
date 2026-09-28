#!/usr/bin/env python3
"""
Streamlit SOC Dashboard for New Datasets Pipeline.

Displays:
  1. Alert table with predictions, confidence, severity
  2. Attack distribution chart
  3. Severity count breakdown
  4. Interactive SHAP explanation panel
  5. Cross-dataset comparison results

Usage:
    streamlit run detection/new_datasets/scripts/dashboard.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

import joblib
import numpy as np
import pandas as pd
import streamlit as st

from detection.new_datasets.config import DATA_MODELS, DATA_RESULTS, DATASET_REGISTRY

st.set_page_config(
    page_title="XAI-IDPS-SOC • New Datasets Dashboard",
    page_icon="🛡️",
    layout="wide",
)


def load_available_results():
    """Check which datasets have trained models."""
    available = []
    for name in DATASET_REGISTRY:
        model_dir = DATA_MODELS / name
        if (model_dir / f"{name}_random_forest.joblib").exists():
            available.append(name)
    return available


def generate_alerts(dataset_name: str, n: int = 50) -> pd.DataFrame:
    """Generate a sample alert table from saved test data."""
    model_dir = DATA_MODELS / dataset_name

    try:
        X_test = joblib.load(model_dir / "X_test.joblib")
        y_test = joblib.load(model_dir / "y_test.joblib")
        le = joblib.load(model_dir / "label_encoder.joblib")
        features = joblib.load(model_dir / "feature_names.joblib")
        model = joblib.load(model_dir / f"{dataset_name}_random_forest.joblib")
    except FileNotFoundError:
        return pd.DataFrame()

    # Sample
    idx = np.random.RandomState(42).choice(
        len(X_test), min(n, len(X_test)), replace=False
    )
    X_sample = X_test[idx]
    y_true = y_test[idx]

    y_pred = model.predict(X_sample)
    y_proba = model.predict_proba(X_sample)

    rows = []
    for i in range(len(idx)):
        conf = float(y_proba[i].max())
        pred_class = le.inverse_transform([y_pred[i]])[0]
        true_class = le.inverse_transform([y_true[i]])[0]

        if conf >= 0.90:
            severity = "🔴 CRITICAL"
        elif conf >= 0.75:
            severity = "🟠 HIGH"
        elif conf >= 0.50:
            severity = "🟡 MEDIUM"
        else:
            severity = "🟢 LOW"

        rows.append(
            {
                "ID": f"ALERT-{i + 1:04d}",
                "Predicted": pred_class,
                "True Label": true_class,
                "Confidence": f"{conf:.1%}",
                "Severity": severity,
                "Correct": "✅" if y_pred[i] == y_true[i] else "❌",
            }
        )

    return pd.DataFrame(rows)


def main():
    st.title("🛡️ XAI-IDPS-SOC • New Datasets Dashboard")
    st.markdown("**IoT & NetFlow Intrusion Detection with Explainability**")
    st.divider()

    available = load_available_results()

    if not available:
        st.warning(
            "⚠️ No trained models found. Run the pipeline first:\n\n"
            "```bash\n"
            "python -m detection.new_datasets.scripts.run_pipeline --all --explain\n"
            "```"
        )
        st.stop()

    # ── Sidebar ───────────────────────────────────────────────────────────
    dataset = st.sidebar.selectbox(
        "Select Dataset",
        available,
        format_func=lambda x: DATASET_REGISTRY[x]["display_name"],
    )

    st.sidebar.markdown("---")
    st.sidebar.markdown(f"**{DATASET_REGISTRY[dataset]['display_name']}**")
    st.sidebar.markdown(DATASET_REGISTRY[dataset]["description"])

    # ── Alert Table ───────────────────────────────────────────────────────
    st.header("🚨 Alert Triage Queue")
    alerts_df = generate_alerts(dataset, n=100)

    if not alerts_df.empty:
        # Severity filter
        severities = alerts_df["Severity"].unique().tolist()
        selected_sev = st.multiselect(
            "Filter by Severity", severities, default=severities
        )
        filtered = alerts_df[alerts_df["Severity"].isin(selected_sev)]
        st.dataframe(filtered, use_container_width=True, height=400)

        # ── Metrics Row ───────────────────────────────────────────────
        col1, col2, col3, col4 = st.columns(4)
        correct = (filtered["Correct"] == "✅").sum()
        total = len(filtered)
        col1.metric("Total Alerts", total)
        col2.metric("Correctly Classified", f"{correct}/{total}")
        col3.metric("Accuracy", f"{correct / total:.1%}" if total > 0 else "N/A")
        critical = (filtered["Severity"].str.contains("CRITICAL")).sum()
        col4.metric("Critical Alerts", critical)

        # ── Attack Distribution ───────────────────────────────────────
        st.header("📊 Attack Distribution")
        dist = filtered["Predicted"].value_counts()
        st.bar_chart(dist)

        # ── Severity Breakdown ────────────────────────────────────────
        st.header("⚡ Severity Breakdown")
        sev_counts = filtered["Severity"].value_counts()
        st.bar_chart(sev_counts)

    # ── Comparison Table ──────────────────────────────────────────────────
    comparison_path = DATA_RESULTS / "comparison_table.csv"
    if comparison_path.exists():
        st.header("📈 Model Comparison (All Datasets)")
        comp_df = pd.read_csv(comparison_path)
        st.dataframe(comp_df, use_container_width=True)

    # ── Cross-Dataset Results ─────────────────────────────────────────────
    cross_path = DATA_RESULTS / "cross_dataset_results.csv"
    if cross_path.exists():
        st.header("🔄 Cross-Dataset Generalization")
        cross_df = pd.read_csv(cross_path)
        st.dataframe(cross_df, use_container_width=True)
        st.info(
            "💡 **Why does performance drop?** IoT datasets use different "
            "device topologies, traffic patterns, and feature distributions. "
            "The NetFlow v3 schema provides the most standardized features, "
            "making cross-dataset transfer more reliable."
        )

    # ── Explanation Panel ─────────────────────────────────────────────────
    st.header("🔍 Alert Explanation Panel")
    st.markdown("Select an alert to see its SHAP-based explanation:")

    if not alerts_df.empty:
        alert_id = st.selectbox("Alert ID", alerts_df["ID"].tolist())
        idx = int(alert_id.split("-")[1]) - 1

        model_dir = DATA_MODELS / dataset
        try:
            X_test = joblib.load(model_dir / "X_test.joblib")
            features = joblib.load(model_dir / "feature_names.joblib")
            le = joblib.load(model_dir / "label_encoder.joblib")
            model = joblib.load(model_dir / f"{dataset}_random_forest.joblib")

            from detection.new_datasets.explainability.explainer import explain_alert

            result = explain_alert(model, X_test[idx], features, le, dataset)

            st.markdown(f"### {result['predicted_class']} — {result['severity']}")
            st.markdown(f"**Confidence:** {result['confidence']:.1%}")
            st.markdown("**Top Contributing Features:**")
            for e in result["top_features"]:
                direction_emoji = "🔴" if "ATTACK" in e["direction"] else "🟢"
                st.markdown(
                    f"- {direction_emoji} **{e['human_name']}**: "
                    f"value={e['observed_value']:.2f}, "
                    f"SHAP={e['shap_value']:+.4f}"
                )
        except Exception as e:
            st.error(f"Explanation unavailable: {e}")


if __name__ == "__main__":
    main()
