"""
Cross-Dataset Generalization Testing.

Train on dataset A → test on dataset B using a shared feature subset.
This is the strongest demonstration for your evaluator because it
reveals how well IDS models transfer across different IoT environments.

Shared feature subset (common across flow-level datasets):
  - Flow duration
  - Packet counts (fwd / bwd / total)
  - Byte counts (fwd / bwd / total)
  - Protocol indicator
  - Flag counts (SYN, ACK, FIN, RST, PSH, URG)
  - Rates (packets/s, bytes/s)

The module finds the best-matching column names across datasets,
intersects them, and evaluates the performance drop.
"""

import logging
from typing import Dict, Any, List, Tuple, Optional

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, f1_score, classification_report,
)

from detection.new_datasets.config import RANDOM_STATE

logger = logging.getLogger(__name__)

# ── Canonical shared feature patterns ─────────────────────────────────────────
# We search for columns whose lowercased name contains these substrings.
# This handles different naming conventions across datasets.

SHARED_FEATURE_PATTERNS = [
    # Duration
    "flow_duration", "duration",
    # Packet counts
    "total_fwd_packet", "total_bwd_packet", "total_packets",
    "fwd_packets", "bwd_packets",
    "in_pkts", "out_pkts",
    # Byte counts
    "total_fwd_byte", "total_bwd_byte", "totlen_fwd",
    "totlen_bwd", "total_length",
    "in_bytes", "out_bytes",
    # Rates
    "flow_bytes/s", "flow_packets/s", "flow_byts_s", "flow_pkts_s",
    "bytes_rate", "pkts_rate",
    # Protocol
    "protocol",
    # Flags
    "syn_flag", "ack_flag", "fin_flag", "rst_flag",
    "psh_flag", "urg_flag",
    "tcp_flags",
    "syn_count", "ack_count", "fin_count",
]


def find_shared_features(
    df_a: pd.DataFrame,
    df_b: pd.DataFrame,
) -> List[str]:
    """
    Find columns present in both DataFrames whose lowercased names
    match any of the shared feature patterns.
    """
    cols_a = set(df_a.columns)
    cols_b = set(df_b.columns)
    common = cols_a & cols_b

    # Also try fuzzy matching via patterns
    matched = set()
    for col in common:
        cl = col.lower().replace(" ", "_")
        for pat in SHARED_FEATURE_PATTERNS:
            if pat.lower() in cl or cl in pat.lower():
                matched.add(col)
                break

    # If exact common set has few pattern matches, try looser matching
    if len(matched) < 5:
        # Fall back to all numeric columns that are common
        num_a = set(df_a.select_dtypes(include=[np.number]).columns)
        num_b = set(df_b.select_dtypes(include=[np.number]).columns)
        matched = num_a & num_b
        # Remove meta columns
        matched -= {"label", "label_binary", "label_original"}

    shared = sorted(matched)
    logger.info(f"  Shared features found: {len(shared)}")
    if len(shared) > 0:
        logger.info(f"  Features: {shared[:15]}{'...' if len(shared) > 15 else ''}")
    return shared


def cross_dataset_test(
    df_train: pd.DataFrame,
    df_test: pd.DataFrame,
    train_name: str,
    test_name: str,
    label_col: str = "label_binary",
) -> Dict[str, Any]:
    """
    Train RF on dataset A, test on dataset B using shared features.
    Uses binary labels (Benign vs Attack) for comparability.

    Returns:
        Dict with metrics, feature list, and performance analysis.
    """
    logger.info(f"\n{'='*60}")
    logger.info(f"Cross-Dataset: Train on {train_name} → Test on {test_name}")
    logger.info(f"{'='*60}")

    shared = find_shared_features(df_train, df_test)
    if len(shared) < 3:
        logger.warning("  Too few shared features for meaningful comparison")
        return {
            "train_dataset": train_name,
            "test_dataset": test_name,
            "shared_features": shared,
            "error": "Insufficient shared features",
        }

    # Prepare data
    X_train = df_train[shared].select_dtypes(include=[np.number])
    y_train = df_train[label_col].astype(int)
    X_test = df_test[shared].select_dtypes(include=[np.number])
    y_test = df_test[label_col].astype(int)

    # Ensure same columns
    common_cols = sorted(set(X_train.columns) & set(X_test.columns))
    X_train = X_train[common_cols].copy()
    X_test = X_test[common_cols].copy()

    # Clean
    X_train = X_train.replace([np.inf, -np.inf], np.nan).fillna(0)
    X_test = X_test.replace([np.inf, -np.inf], np.nan).fillna(0)

    # Scale
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    # Train RF on dataset A
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        class_weight="balanced",
    )
    rf.fit(X_train_s, y_train)

    # Evaluate on dataset A (in-domain baseline)
    y_pred_train = rf.predict(X_train_s)
    acc_in = accuracy_score(y_train, y_pred_train)
    f1_in = f1_score(y_train, y_pred_train, average="macro", zero_division=0)

    # Evaluate on dataset B (cross-domain)
    y_pred_test = rf.predict(X_test_s)
    acc_cross = accuracy_score(y_test, y_pred_test)
    f1_cross = f1_score(y_test, y_pred_test, average="macro", zero_division=0)

    # Performance drop
    acc_drop = acc_in - acc_cross
    f1_drop = f1_in - f1_cross

    result = {
        "train_dataset": train_name,
        "test_dataset": test_name,
        "shared_features": common_cols,
        "n_shared_features": len(common_cols),
        "in_domain_accuracy": acc_in,
        "in_domain_f1_macro": f1_in,
        "cross_domain_accuracy": acc_cross,
        "cross_domain_f1_macro": f1_cross,
        "accuracy_drop": acc_drop,
        "f1_drop": f1_drop,
        "report": classification_report(
            y_test, y_pred_test,
            target_names=["Benign", "Attack"],
            zero_division=0,
        ),
    }

    logger.info(f"  In-domain  → Acc={acc_in:.4f}  F1m={f1_in:.4f}")
    logger.info(f"  Cross-dom  → Acc={acc_cross:.4f}  F1m={f1_cross:.4f}")
    logger.info(f"  Drop       → Acc={acc_drop:+.4f}  F1m={f1_drop:+.4f}")
    logger.info(f"\n{result['report']}")

    return result


def run_all_cross_tests(
    datasets: Dict[str, pd.DataFrame],
) -> List[Dict[str, Any]]:
    """
    Run pairwise cross-dataset tests for all dataset combinations.

    Args:
        datasets: {'name': DataFrame} dict with loaded, label-mapped data.

    Returns:
        List of result dicts.
    """
    names = sorted(datasets.keys())
    results = []
    for i, a in enumerate(names):
        for j, b in enumerate(names):
            if i == j:
                continue
            r = cross_dataset_test(datasets[a], datasets[b], a, b)
            results.append(r)
    return results


def build_cross_table(results: List[Dict[str, Any]]) -> pd.DataFrame:
    """Build a summary table of cross-dataset results."""
    rows = []
    for r in results:
        if "error" in r:
            continue
        rows.append({
            "Train On": r["train_dataset"],
            "Test On": r["test_dataset"],
            "Shared Features": r["n_shared_features"],
            "In-Domain Acc": f"{r['in_domain_accuracy']:.4f}",
            "Cross Acc": f"{r['cross_domain_accuracy']:.4f}",
            "Acc Drop": f"{r['accuracy_drop']:+.4f}",
            "In-Domain F1m": f"{r['in_domain_f1_macro']:.4f}",
            "Cross F1m": f"{r['cross_domain_f1_macro']:.4f}",
            "F1 Drop": f"{r['f1_drop']:+.4f}",
        })
    return pd.DataFrame(rows)
