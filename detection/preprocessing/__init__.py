"""
Data Loader for CICIDS2017 and UNSW-NB15 datasets.

Handles:
- Loading raw CSV files from detection/data/raw/
- Initial cleaning (NaN, Infinity, duplicates)
- Label normalization
- Dataset-specific preprocessing
"""

import logging
import os
from pathlib import Path
from typing import Optional, Tuple

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent
RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw"
PROCESSED_DATA_DIR = PROJECT_ROOT / "data" / "processed"


# ── CICIDS2017 Configuration ──────────────────────────────────────────────────

CICIDS2017_FILES = [
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
]

# Label column name in CICIDS2017
CICIDS2017_LABEL_COL = " Label"  # Note: leading space in original CSV

# Standardized label mapping for CICIDS2017
CICIDS2017_LABEL_MAP = {
    "BENIGN": "Benign",
    "FTP-Patator": "FTP-Patator",
    "SSH-Patator": "SSH-Patator",
    "DoS Hulk": "DoS Hulk",
    "DoS GoldenEye": "DoS GoldenEye",
    "DoS slowloris": "DoS slowloris",
    "DoS Slowhttptest": "DoS Slowhttptest",
    "Heartbleed": "Heartbleed",
    "Web Attack \x96 Brute Force": "Web Attack - Brute Force",
    "Web Attack \x96 XSS": "Web Attack - XSS",
    "Web Attack \x96 Sql Injection": "Web Attack - Sql Injection",
    "Web Attack – Brute Force": "Web Attack - Brute Force",
    "Web Attack – XSS": "Web Attack - XSS",
    "Web Attack – Sql Injection": "Web Attack - Sql Injection",
    "Infiltration": "Infiltration",
    "Bot": "Bot",
    "PortScan": "PortScan",
    "DDoS": "DDoS",
}


# ── CSE-CIC-IDS2018 Configuration ─────────────────────────────────────────────

CIC_IDS2018_LABEL_COL = "Label"

# Standardized label mapping for CSE-CIC-IDS2018
CIC_IDS2018_LABEL_MAP = {
    "Benign": "Benign",
    "BENIGN": "Benign",
    "FTP-BruteForce": "FTP-BruteForce",
    "SSH-Bruteforce": "SSH-Bruteforce",
    "DoS attacks-GoldenEye": "DoS attacks-GoldenEye",
    "DoS attacks-Slowloris": "DoS attacks-Slowloris",
    "DoS attacks-SlowHTTPTest": "DoS attacks-SlowHTTPTest",
    "DoS attacks-Hulk": "DoS attacks-Hulk",
    "DDOS attack-LOIC-UDP": "DDOS attack-LOIC-UDP",
    "DDOS attack-HOIC": "DDOS attack-HOIC",
    "DDoS attacks-LOIC-HTTP": "DDoS attacks-LOIC-HTTP",
    "Brute Force -Web": "Brute Force -Web",
    "Brute Force -XSS": "Brute Force -XSS",
    "SQL Injection": "SQL Injection",
    "Infilteration": "Infilteration",
    "Bot": "Bot",
}


def load_cic_ids2018(
    data_dir: Path | None = None, sample_frac: float | None = None
) -> pd.DataFrame:
    """
    Load and merge all CSE-CIC-IDS2018 CSV files.

    Args:
        data_dir: Directory containing the CSV files. Defaults to RAW_DATA_DIR / 'cse-cic-ids2018'.
        sample_frac: If set, randomly sample this fraction of the data.

    Returns:
        Merged DataFrame with standardized column names and normalized labels.
    """
    if data_dir is None:
        data_dir = RAW_DATA_DIR / "cse-cic-ids2018"

    if not data_dir.exists():
        raise FileNotFoundError(
            f"CSE-CIC-IDS2018 data directory not found: {data_dir}\n"
            f"Please download the dataset using scripts/download_cic_ids2018.py"
        )

    csv_files = sorted(list(data_dir.glob("*.csv")))
    if not csv_files:
        raise FileNotFoundError(f"No CSE-CIC-IDS2018 CSV files found in {data_dir}")

    dfs = []
    for filepath in csv_files:
        logger.info(f"Loading {filepath.name}...")
        df = pd.read_csv(filepath, low_memory=False)
        df.columns = df.columns.str.strip()
        # Drop repeated header lines if present in concatenated CSVs
        if "Label" in df.columns:
            df = df[df["Label"] != "Label"]
        dfs.append(df)
        logger.info(f"  → {len(df)} records loaded")

    df = pd.concat(dfs, ignore_index=True)
    logger.info(f"Total CSE-CIC-IDS2018 records loaded: {len(df)}")

    # Standardize column names
    df.columns = df.columns.str.strip()

    # Standardize labels
    if "Label" in df.columns:
        df["Label"] = (
            df["Label"]
            .astype(str)
            .str.strip()
            .map(lambda x: CIC_IDS2018_LABEL_MAP.get(x, x))
        )

    if sample_frac is not None and 0 < sample_frac < 1:
        df = df.sample(frac=sample_frac, random_state=42).reset_index(drop=True)
        logger.info(f"Sampled to {len(df)} records ({sample_frac * 100:.0f}%)")

    return df


# ── UNSW-NB15 Configuration ──────────────────────────────────────────────────

UNSW_NB15_TRAIN_FILE = "UNSW_NB15_training-set.csv"
UNSW_NB15_TEST_FILE = "UNSW_NB15_testing-set.csv"
UNSW_NB15_LABEL_COL = "label"
UNSW_NB15_ATTACK_CAT_COL = "attack_cat"


def load_cicids2017(
    data_dir: Path | None = None, sample_frac: float | None = None
) -> pd.DataFrame:
    """
    Load and merge all CICIDS2017 CSV files.

    Args:
        data_dir: Directory containing the CSV files. Defaults to RAW_DATA_DIR / 'cicids2017'.
        sample_frac: If set, randomly sample this fraction of the data (useful for development).

    Returns:
        Merged DataFrame with standardized column names and labels.
    """
    if data_dir is None:
        data_dir = RAW_DATA_DIR / "cicids2017"

    if not data_dir.exists():
        raise FileNotFoundError(
            f"CICIDS2017 data directory not found: {data_dir}\n"
            f"Please download the dataset and place CSV files in {data_dir}\n"
            f"Download from: https://www.unb.ca/cic/datasets/ids-2017.html"
        )

    dfs = []
    for filename in CICIDS2017_FILES:
        filepath = data_dir / filename
        if filepath.exists():
            logger.info(f"Loading {filename}...")
            df = pd.read_csv(filepath, encoding="utf-8", low_memory=False)
            dfs.append(df)
            logger.info(f"  → {len(df)} records loaded")
        else:
            logger.warning(f"File not found, skipping: {filepath}")

    if not dfs:
        raise FileNotFoundError(f"No CICIDS2017 CSV files found in {data_dir}")

    df = pd.concat(dfs, ignore_index=True)
    logger.info(f"Total CICIDS2017 records loaded: {len(df)}")

    # Standardize column names: strip whitespace
    df.columns = df.columns.str.strip()

    # Rename label column if needed
    if "Label" not in df.columns and " Label" in df.columns:
        df.rename(columns={" Label": "Label"}, inplace=True)

    # Standardize labels
    df["Label"] = df["Label"].str.strip().map(lambda x: CICIDS2017_LABEL_MAP.get(x, x))

    if sample_frac is not None and 0 < sample_frac < 1:
        df = df.sample(frac=sample_frac, random_state=42).reset_index(drop=True)
        logger.info(f"Sampled to {len(df)} records ({sample_frac * 100:.0f}%)")

    return df


def load_unsw_nb15(
    data_dir: Path | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Load UNSW-NB15 training and testing sets.

    Args:
        data_dir: Directory containing the CSV files. Defaults to RAW_DATA_DIR / 'unsw_nb15'.

    Returns:
        Tuple of (train_df, test_df).
    """
    if data_dir is None:
        data_dir = RAW_DATA_DIR / "unsw_nb15"

    if not data_dir.exists():
        raise FileNotFoundError(
            f"UNSW-NB15 data directory not found: {data_dir}\n"
            f"Please download the dataset and place CSV files in {data_dir}\n"
            f"Download from: https://research.unsw.edu.au/projects/unsw-nb15-dataset"
        )

    train_path = data_dir / UNSW_NB15_TRAIN_FILE
    test_path = data_dir / UNSW_NB15_TEST_FILE

    if not train_path.exists() or not test_path.exists():
        raise FileNotFoundError(
            f"UNSW-NB15 train/test files not found in {data_dir}\n"
            f"Expected: {UNSW_NB15_TRAIN_FILE} and {UNSW_NB15_TEST_FILE}"
        )

    logger.info("Loading UNSW-NB15 training set...")
    train_df = pd.read_csv(train_path, low_memory=False)
    logger.info(f"  → {len(train_df)} training records")

    logger.info("Loading UNSW-NB15 testing set...")
    test_df = pd.read_csv(test_path, low_memory=False)
    logger.info(f"  → {len(test_df)} testing records")

    # Standardize column names
    for df in [train_df, test_df]:
        df.columns = df.columns.str.strip()

        # Clean attack_cat column
        if UNSW_NB15_ATTACK_CAT_COL in df.columns:
            df[UNSW_NB15_ATTACK_CAT_COL] = (
                df[UNSW_NB15_ATTACK_CAT_COL]
                .fillna("Normal")
                .str.strip()
                .replace({"": "Normal", " ": "Normal"})
            )

    return train_df, test_df


def clean_dataframe(df: pd.DataFrame, label_col: str = "Label") -> pd.DataFrame:
    """
    Clean a DataFrame: remove NaN, Infinity, and duplicate rows.

    Args:
        df: Input DataFrame.
        label_col: Name of the label column.

    Returns:
        Cleaned DataFrame.
    """
    initial_len = len(df)

    # Get numeric columns only
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()

    # Replace infinity with NaN
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)

    # Count and report NaN
    nan_count = df[numeric_cols].isna().sum().sum()
    if nan_count > 0:
        logger.info(
            f"Dropping rows with NaN/Infinity values ({nan_count} NaN cells found)"
        )
        df = df.dropna(subset=numeric_cols)

    # Remove duplicates
    dup_count = df.duplicated().sum()
    if dup_count > 0:
        logger.info(f"Removing {dup_count} duplicate rows")
        df = df.drop_duplicates()

    # Remove rows with missing labels
    if label_col in df.columns:
        null_labels = df[label_col].isna().sum()
        if null_labels > 0:
            logger.info(f"Removing {null_labels} rows with null labels")
            df = df.dropna(subset=[label_col])

    df = df.reset_index(drop=True)
    logger.info(
        f"Cleaning: {initial_len} → {len(df)} records ({initial_len - len(df)} removed)"
    )

    return df


def get_class_distribution(df: pd.DataFrame, label_col: str = "Label") -> pd.DataFrame:
    """
    Get class distribution statistics.

    Args:
        df: DataFrame with labels.
        label_col: Name of the label column.

    Returns:
        DataFrame with class counts and percentages.
    """
    dist = df[label_col].value_counts().reset_index()
    dist.columns = ["Class", "Count"]
    dist["Percentage"] = (dist["Count"] / len(df) * 100).round(2)
    return dist


# ── BETH Host Telemetry Integration ───────────────────────────────────────────
from detection.preprocessing.load_beth import (
    correlate_host_network,
    extract_beth_features,
    load_beth_dataset,
)
