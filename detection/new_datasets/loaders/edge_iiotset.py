"""
Edge-IIoTset Dataset Loader.

Source:  Kaggle – Edge-IIoT Dataset (ML-ready version)
URL:     https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot

The dataset targets edge/industrial IoT environments and ships with
pre-selected ML and DL feature subsets.  We use the ML version
(ML-EdgeIIoT-dataset.csv) which contains ~157 K rows and 61 features.

Attack categories: DDoS, DoS, Reconnaissance, Password (Brute Force),
  MITM, Injection (SQL, XSS), Ransomware, Backdoor, Fingerprinting, …

Place the CSV in:  detection/data/raw/edge_iiotset/
"""

import logging
from pathlib import Path

import numpy as np
import pandas as pd

from detection.new_datasets.config import RANDOM_STATE

logger = logging.getLogger(__name__)

COLS_TO_DROP = [
    "frame.time",
    "ip.src_host",
    "ip.dst_host",
    "arp.src.proto_ipv4",
    "arp.dst.proto_ipv4",
    "ip.src",
    "ip.dst",
    # possible alternate names
    "src_ip",
    "dst_ip",
    "timestamp",
]

# ── Label mapping → unified multi-class scheme ───────────────────────────────
LABEL_MAP = {
    # Benign
    "Normal": "Benign",
    "normal": "Benign",
    # DDoS
    "DDoS_UDP": "DoS/DDoS",
    "DDoS_ICMP": "DoS/DDoS",
    "DDoS_TCP": "DoS/DDoS",
    "DDoS_HTTP": "DoS/DDoS",
    # DoS
    "DoS_UDP": "DoS/DDoS",
    "DoS_TCP": "DoS/DDoS",
    "DoS_HTTP": "DoS/DDoS",
    # Reconnaissance / Scanning / Fingerprinting
    "Vulnerability_scanner": "Recon",
    "Port_Scanning": "Recon",
    "OS_Fingerprinting": "Recon",
    "Fingerprinting": "Recon",
    # Brute Force / Password
    "Password": "Brute Force",
    "Brute_Force": "Brute Force",
    # MITM / Spoofing
    "MITM": "Spoofing",
    "ARP_Spoofing": "Spoofing",
    "DNS_Spoofing": "Spoofing",
    # Web / Injection attacks
    "SQL_injection": "Web",
    "Uploading": "Web",
    "XSS": "Web",
    # Malware
    "Ransomware": "Malware/Botnet/Mirai",
    "Backdoor": "Malware/Botnet/Mirai",
}


def load_edge_iiotset(
    data_dir: Path | None = None,
    sample_frac: float = 1.0,
) -> pd.DataFrame:
    """
    Load the Edge-IIoTset ML-ready CSV, clean, and map labels.

    Returns:
        DataFrame with unified 'label', 'label_binary', and 'label_original'.
    """
    if data_dir is None:
        from detection.new_datasets.config import DATA_RAW

        data_dir = DATA_RAW / "edge_iiotset"

    if not data_dir.exists():
        data_dir.mkdir(parents=True, exist_ok=True)

    csv_files = sorted(data_dir.glob("*.csv"))
    if not csv_files:
        from detection.new_datasets.scripts.generate_sample_data import (
            generate_edge_iiotset_sample,
        )

        logger.info(f"Generating Edge-IIoTset benchmark sample in {data_dir}...")
        generate_edge_iiotset_sample(3000, save=True)
        csv_files = sorted(data_dir.glob("*.csv"))

    # Prefer the ML-ready file if present
    target = None
    for f in csv_files:
        if "ml" in f.name.lower() or "ML" in f.name:
            target = f
            break
    if target is None:
        target = csv_files[0]

    logger.info(f"Loading Edge-IIoTset from {target.name} ...")
    df = pd.read_csv(target, low_memory=False)
    logger.info(f"  Raw rows: {len(df):,}")

    # ── Standardize column names (strip whitespace) ────────────────────────
    df.columns = df.columns.str.strip()

    # ── Identify label column ─────────────────────────────────────────────
    label_col = None
    for candidate in [
        "Attack_type",
        "attack_type",
        "Attack_label",
        "attack_label",
        "label",
        "Label",
        "Attack",
    ]:
        if candidate in df.columns:
            label_col = candidate
            break
    if label_col is None:
        raise KeyError(f"Cannot find label column. Columns: {list(df.columns)}")

    # ── Drop identifier columns ───────────────────────────────────────────
    drop = [c for c in COLS_TO_DROP if c in df.columns]
    if drop:
        df.drop(columns=drop, inplace=True, errors="ignore")
        logger.info(f"  Dropped: {drop}")

    # ── Clean numerics & handle NaN/inf & drop duplicates ──────────────────
    df = _clean_numerics(df, label_col)

    # ── Map labels ────────────────────────────────────────────────────────
    raw_labels = df[label_col].astype(str).str.strip()
    df["label_original"] = raw_labels
    df["label"] = raw_labels.map(lambda x: LABEL_MAP.get(x, "APT/Other"))
    df["label_binary"] = df["label"].apply(lambda x: 0 if x == "Benign" else 1)

    if label_col not in ("label",):
        df.drop(columns=[label_col], inplace=True, errors="ignore")

    # ── Optional sample ───────────────────────────────────────────────────
    if 0 < sample_frac < 1.0:
        df = (
            df.groupby("label", group_keys=False)
            .apply(lambda g: g.sample(frac=sample_frac, random_state=RANDOM_STATE))
            .reset_index(drop=True)
        )
        logger.info(f"  Sampled ({sample_frac * 100:.0f}%): {len(df):,} rows")

    logger.info(f"Edge-IIoTset loaded: {len(df):,} rows, {df.shape[1]} cols")
    return df


def _clean_numerics(df: pd.DataFrame, label_col: str) -> pd.DataFrame:
    """Replace inf, drop NaN rows, remove duplicates."""
    num_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    df[num_cols] = df[num_cols].replace([np.inf, -np.inf], np.nan)
    before = len(df)
    df.dropna(subset=num_cols, inplace=True)
    df.drop_duplicates(inplace=True)
    df.reset_index(drop=True, inplace=True)
    logger.info(
        f"  Cleaning: {before:,} → {len(df):,} rows ({before - len(df):,} removed)"
    )
    return df
