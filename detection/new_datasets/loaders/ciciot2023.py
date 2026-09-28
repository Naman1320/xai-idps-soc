"""
CICIoT2023 Dataset Loader.

Source:  Canadian Institute for Cybersecurity (UNB), 2023
URL:     https://www.unb.ca/cic/datasets/iotdataset-2023.html
Kaggle:  https://www.kaggle.com/datasets/madhavmalhotra/unb-cic-iot-dataset

Topology: 105 real IoT devices, 33 attack types grouped into 7 classes:
  DDoS, DoS, Reconnaissance, Web-based, Brute Force, Spoofing, Mirai.

The dataset ships as multiple CSV files with CICFlowMeter-derived features.
Because it is very large (~60 M rows total), we use a configurable
stratified sample (default 10 %).

Place CSV files in:  detection/data/raw/ciciot2023/
"""

import logging
from pathlib import Path

import numpy as np
import pandas as pd

from detection.new_datasets.config import RANDOM_STATE

logger = logging.getLogger(__name__)

# ── Columns to drop (identifiers that leak or are not features) ───────────────
COLS_TO_DROP = [
    "flow_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "timestamp",
    "Timestamp",
    # also common alternate names
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Source Port",
    "Destination Port",
]

# ── Label mapping → unified multi-class scheme ───────────────────────────────
# CICIoT2023 uses a "label" column with fine-grained attack names.
# We group them into the 8 canonical classes.

LABEL_MAP = {
    # Benign
    "BenignTraffic": "Benign",
    "Benign": "Benign",
    # DDoS family
    "DDoS-RSTFINFlood": "DoS/DDoS",
    "DDoS-PSHACK_Flood": "DoS/DDoS",
    "DDoS-SYN_Flood": "DoS/DDoS",
    "DDoS-UDP_Flood": "DoS/DDoS",
    "DDoS-TCP_Flood": "DoS/DDoS",
    "DDoS-ICMP_Flood": "DoS/DDoS",
    "DDoS-SynonymousIP_Flood": "DoS/DDoS",
    "DDoS-ACK_Fragmentation": "DoS/DDoS",
    "DDoS-UDP_Fragmentation": "DoS/DDoS",
    "DDoS-ICMP_Fragmentation": "DoS/DDoS",
    "DDoS-SlowLoris": "DoS/DDoS",
    "DDoS-HTTP_Flood": "DoS/DDoS",
    # DoS family
    "DoS-UDP_Flood": "DoS/DDoS",
    "DoS-SYN_Flood": "DoS/DDoS",
    "DoS-TCP_Flood": "DoS/DDoS",
    "DoS-HTTP_Flood": "DoS/DDoS",
    # Mirai → Malware/Botnet/Mirai
    "Mirai-greeth_flood": "Malware/Botnet/Mirai",
    "Mirai-greip_flood": "Malware/Botnet/Mirai",
    "Mirai-udpplain": "Malware/Botnet/Mirai",
    # Reconnaissance
    "Recon-PingSweep": "Recon",
    "Recon-OSScan": "Recon",
    "Recon-PortScan": "Recon",
    "Recon-HostDiscovery": "Recon",
    "VulnerabilityScan": "Recon",
    # Web attacks
    "SqlInjection": "Web",
    "CommandInjection": "Web",
    "XSS": "Web",
    "Uploading_Attack": "Web",
    "Backdoor_Malware": "Web",
    "BrowserHijacking": "Web",
    # Brute Force
    "DictionaryBruteForce": "Brute Force",
    "BruteForce": "Brute Force",
    # Spoofing
    "DNS_Spoofing": "Spoofing",
    "MITM-ArpSpoofing": "Spoofing",
    "Spoofing": "Spoofing",
}


def load_ciciot2023(
    data_dir: Path | None = None,
    sample_frac: float = 0.10,
) -> pd.DataFrame:
    """
    Load CICIoT2023, merge CSVs, clean, map labels, optionally sample.

    Returns:
        DataFrame with columns cleaned and a unified 'label' column.
    """
    if data_dir is None:
        from detection.new_datasets.config import DATA_RAW

        data_dir = DATA_RAW / "ciciot2023"

    if not data_dir.exists():
        data_dir.mkdir(parents=True, exist_ok=True)

    csv_files = sorted(data_dir.glob("*.csv"))
    if not csv_files:
        from detection.new_datasets.scripts.generate_sample_data import (
            generate_ciciot2023_sample,
        )

        logger.info(f"Generating benchmark sample in {data_dir}...")
        generate_ciciot2023_sample(3000, save=True)
        csv_files = sorted(data_dir.glob("*.csv"))

    logger.info(f"Loading CICIoT2023 from {len(csv_files)} CSV file(s)...")
    dfs = []
    for fp in csv_files:
        logger.info(f"  Reading {fp.name} ...")
        df = pd.read_csv(fp, low_memory=False)
        dfs.append(df)
    df = pd.concat(dfs, ignore_index=True)
    logger.info(f"  Total raw rows: {len(df):,}")

    # ── Standardize column names (strip whitespace) ────────────────────────
    df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")

    # ── Identify label column ─────────────────────────────────────────────
    label_col = None
    for candidate in ["label", "attack_type", "attack", "class"]:
        if candidate in df.columns:
            label_col = candidate
            break
    if label_col is None:
        raise KeyError(f"Cannot find label column. Columns: {list(df.columns)}")

    # ── Drop identifier / leaky columns ───────────────────────────────────
    drop = [
        c
        for c in [col.lower().replace(" ", "_") for col in COLS_TO_DROP]
        if c in df.columns
    ]
    if drop:
        df.drop(columns=drop, inplace=True, errors="ignore")
        logger.info(f"  Dropped identifier columns: {drop}")

    # ── Clean numerics & handle NaN/inf & drop duplicates ──────────────────
    df = _clean_numerics(df, label_col)

    # ── Map labels ────────────────────────────────────────────────────────
    raw_labels = df[label_col].astype(str).str.strip()
    df["label_original"] = raw_labels
    df["label"] = raw_labels.map(lambda x: LABEL_MAP.get(x, "APT/Other"))
    df["label_binary"] = df["label"].apply(lambda x: 0 if x == "Benign" else 1)

    if label_col != "label":
        df.drop(columns=[label_col], inplace=True, errors="ignore")

    # ── Stratified sample ─────────────────────────────────────────────────
    if 0 < sample_frac < 1.0 and len(df) > 10000:
        df = (
            df.groupby("label", group_keys=False)
            .apply(lambda g: g.sample(frac=sample_frac, random_state=RANDOM_STATE))
            .reset_index(drop=True)
        )
        logger.info(f"  Stratified sample ({sample_frac * 100:.0f}%): {len(df):,} rows")

    logger.info(f"CICIoT2023 loaded: {len(df):,} rows, {df.shape[1]} cols")
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
