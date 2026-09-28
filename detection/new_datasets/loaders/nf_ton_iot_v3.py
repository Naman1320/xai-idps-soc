"""
NF-ToN-IoT-v3 Dataset Loader.

Source:  University of Queensland – NetFlow Datasets v3 (2025)
URL:     https://staff.itee.uq.edu.au/marius/NIDS_datasets/
Kaggle:  https://www.kaggle.com/datasets/dhoogla/nftoniotv3

Schema: 53 extended NetFlow features, binary ('Label') and
        multi-class ('Attack') columns.

Attack types (9): scanning, dos, ddos, injection, password,
  xss, backdoor, ransomware, mitm.

Place CSV(s) in:  detection/data/raw/nf_ton_iot_v3/
"""

import logging
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

from detection.new_datasets.config import RANDOM_STATE

logger = logging.getLogger(__name__)

# NetFlow ID / meta columns to drop
COLS_TO_DROP = [
    "IPV4_SRC_ADDR", "IPV4_DST_ADDR",
    "L4_SRC_PORT", "L4_DST_PORT",
    "FLOW_ID",
    # Lowercase variants
    "ipv4_src_addr", "ipv4_dst_addr",
    "l4_src_port", "l4_dst_port",
    "flow_id",
]

# ── Label mapping → unified multi-class scheme ───────────────────────────────
LABEL_MAP = {
    # Benign
    "Normal":       "Benign",
    "normal":       "Benign",
    "Benign":       "Benign",
    "benign":       "Benign",

    # DoS / DDoS
    "dos":          "DoS/DDoS",
    "DoS":          "DoS/DDoS",
    "ddos":         "DoS/DDoS",
    "DDoS":         "DoS/DDoS",

    # Reconnaissance
    "scanning":     "Recon/Scan",
    "Scanning":     "Recon/Scan",
    "Reconnaissance": "Recon/Scan",

    # Injection / Web
    "injection":    "Web Attacks",
    "Injection":    "Web Attacks",
    "xss":          "Web Attacks",
    "XSS":          "Web Attacks",

    # Brute Force
    "password":     "Brute Force",
    "Password":     "Brute Force",

    # MITM
    "mitm":         "Spoofing/MITM",
    "MITM":         "Spoofing/MITM",

    # Malware
    "backdoor":     "Malware/Botnet",
    "Backdoor":     "Malware/Botnet",
    "ransomware":   "Malware/Botnet",
    "Ransomware":   "Malware/Botnet",
}


def load_nf_ton_iot_v3(
    data_dir: Optional[Path] = None,
    sample_frac: float = 1.0,
) -> pd.DataFrame:
    """
    Load NF-ToN-IoT-v3 CSV(s), clean, and map labels.

    Returns:
        DataFrame with unified 'label', 'label_binary', and 'label_original'.
    """
    if data_dir is None:
        from detection.new_datasets.config import DATA_RAW
        data_dir = DATA_RAW / "nf_ton_iot_v3"

    if not data_dir.exists():
        raise FileNotFoundError(
            f"NF-ToN-IoT-v3 data directory not found: {data_dir}\n"
            "Download from: https://staff.itee.uq.edu.au/marius/NIDS_datasets/\n"
            "  or Kaggle:   https://www.kaggle.com/datasets/dhoogla/nftoniotv3\n"
            f"Place CSV files in: {data_dir}/"
        )

    csv_files = sorted(data_dir.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")

    logger.info(f"Loading NF-ToN-IoT-v3 from {len(csv_files)} file(s)...")
    dfs = []
    for fp in csv_files:
        logger.info(f"  Reading {fp.name} ...")
        df = pd.read_csv(fp, low_memory=False)
        dfs.append(df)
    df = pd.concat(dfs, ignore_index=True)
    logger.info(f"  Total raw rows: {len(df):,}")

    # ── Standardize column names (keep original case for NetFlow) ─────────
    df.columns = df.columns.str.strip()

    # ── Identify label columns ────────────────────────────────────────────
    # NetFlow v3 typically has 'Label' (binary) and 'Attack' (multi-class)
    multi_col = None
    for candidate in ["Attack", "attack", "Attack_type", "attack_type",
                       "Attack_label"]:
        if candidate in df.columns:
            multi_col = candidate
            break

    binary_col = None
    for candidate in ["Label", "label"]:
        if candidate in df.columns:
            binary_col = candidate
            break

    if multi_col is None and binary_col is None:
        raise KeyError(
            f"Cannot find label column.  Columns: {list(df.columns)}"
        )

    # ── Drop identifier columns ───────────────────────────────────────────
    drop = [c for c in COLS_TO_DROP if c in df.columns]
    if drop:
        df.drop(columns=drop, inplace=True, errors="ignore")
        logger.info(f"  Dropped: {drop}")

    # ── Clean numerics ────────────────────────────────────────────────────
    df = _clean_numerics(df)

    # ── Map labels ────────────────────────────────────────────────────────
    if multi_col:
        raw_labels = df[multi_col].astype(str).str.strip()
        df["label_original"] = raw_labels
        df["label"] = raw_labels.map(lambda x: LABEL_MAP.get(x, "Other"))
        if multi_col not in ("label",):
            df.drop(columns=[multi_col], inplace=True, errors="ignore")
    else:
        # Only binary label available
        df["label_original"] = df[binary_col].astype(str)
        df["label"] = df[binary_col].apply(
            lambda x: "Benign" if str(x).strip() in ("0", "Normal", "Benign")
            else "Other"
        )

    df["label_binary"] = df["label"].apply(lambda x: 0 if x == "Benign" else 1)

    if binary_col and binary_col in df.columns and binary_col != "label":
        df.drop(columns=[binary_col], inplace=True, errors="ignore")

    # ── Optional sample ───────────────────────────────────────────────────
    if 0 < sample_frac < 1.0:
        df = (
            df.groupby("label", group_keys=False)
              .apply(lambda g: g.sample(frac=sample_frac, random_state=RANDOM_STATE))
              .reset_index(drop=True)
        )
        logger.info(f"  Sampled ({sample_frac*100:.0f}%): {len(df):,} rows")

    logger.info(f"NF-ToN-IoT-v3 loaded: {len(df):,} rows, {df.shape[1]} cols")
    return df


def _clean_numerics(df: pd.DataFrame) -> pd.DataFrame:
    """Replace inf, drop NaN rows, remove duplicates."""
    num_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    df[num_cols] = df[num_cols].replace([np.inf, -np.inf], np.nan)
    before = len(df)
    df.dropna(subset=num_cols, inplace=True)
    df.drop_duplicates(inplace=True)
    df.reset_index(drop=True, inplace=True)
    logger.info(f"  Cleaning: {before:,} → {len(df):,} rows "
                f"({before - len(df):,} removed)")
    return df
