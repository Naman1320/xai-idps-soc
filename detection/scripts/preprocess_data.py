#!/usr/bin/env python3
"""
Preprocess dataset: Load raw CSV → Clean → Feature extract → Normalize → Split → Save.

Usage:
    python scripts/preprocess_data.py --dataset cicids2017
    python scripts/preprocess_data.py --dataset unsw_nb15
    python scripts/preprocess_data.py --dataset cicids2017 --sample 0.1  # 10% sample for dev
"""

import argparse
import logging
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from detection.preprocessing import (
    load_cicids2017,
    load_cic_ids2018,
    load_unsw_nb15,
    clean_dataframe,
    get_class_distribution,
)
from detection.preprocessing.preprocessor import DataPreprocessor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def preprocess_cicids2017(sample_frac=None):
    """Preprocess CICIDS2017 dataset."""
    logger.info("=" * 60)
    logger.info("PREPROCESSING CICIDS2017")
    logger.info("=" * 60)

    # Load
    df = load_cicids2017(sample_frac=sample_frac)

    # Clean
    df = clean_dataframe(df, label_col="Label")

    # Class distribution
    dist = get_class_distribution(df, label_col="Label")
    logger.info(f"\nClass distribution:\n{dist.to_string(index=False)}")

    # Prepare features
    preprocessor = DataPreprocessor(dataset_name="cicids2017")
    X, y = preprocessor.prepare_features(df, remove_constant=True, remove_high_corr=False)

    # Fit and transform
    X_scaled, y_encoded = preprocessor.fit_transform(X, y)

    # Split
    splits = preprocessor.split_data(X_scaled, y_encoded)

    # Save
    preprocessor.save_artifacts()
    preprocessor.save_splits(splits)

    logger.info("CICIDS2017 preprocessing complete!")
    return preprocessor, splits


def preprocess_unsw_nb15():
    """Preprocess UNSW-NB15 dataset."""
    logger.info("=" * 60)
    logger.info("PREPROCESSING UNSW-NB15")
    logger.info("=" * 60)

    # Load (uses standard train/test split)
    train_df, test_df = load_unsw_nb15()

    # Clean
    train_df = clean_dataframe(train_df, label_col="attack_cat")
    test_df = clean_dataframe(test_df, label_col="attack_cat")

    # Class distribution
    dist = get_class_distribution(train_df, label_col="attack_cat")
    logger.info(f"\nTraining class distribution:\n{dist.to_string(index=False)}")

    # Prepare features
    preprocessor = DataPreprocessor(dataset_name="unsw_nb15")
    X_train, y_train = preprocessor.prepare_features(train_df, remove_constant=True)

    # Fit on train
    X_train_scaled, y_train_encoded = preprocessor.fit_transform(X_train, y_train)

    # Transform test with same preprocessor
    X_test_raw, y_test = preprocessor.prepare_features.__wrapped__(preprocessor, test_df) if hasattr(preprocessor.prepare_features, '__wrapped__') else (
        test_df.drop(columns=[c for c in preprocessor.columns_to_drop if c in test_df.columns], errors="ignore").select_dtypes(include=["number"]),
        test_df[preprocessor.label_col]
    )
    # Ensure same feature columns
    for col in preprocessor.feature_names:
        if col not in X_test_raw.columns:
            X_test_raw[col] = 0
    X_test_raw = X_test_raw[preprocessor.feature_names]
    X_test_scaled = preprocessor.scaler.transform(X_test_raw)
    y_test_encoded = preprocessor.label_encoder.transform(y_test)

    # Create validation split from training data
    from sklearn.model_selection import train_test_split
    X_train_final, X_val, y_train_final, y_val = train_test_split(
        X_train_scaled, y_train_encoded,
        test_size=0.176,  # ~15% of total (15/85 ≈ 0.176)
        random_state=42,
        stratify=y_train_encoded,
    )

    splits = {
        "X_train": X_train_final,
        "y_train": y_train_final,
        "X_val": X_val,
        "y_val": y_val,
        "X_test": X_test_scaled,
        "y_test": y_test_encoded,
    }

    # Save
    preprocessor.save_artifacts()
    preprocessor.save_splits(splits)

    logger.info("UNSW-NB15 preprocessing complete!")
    return preprocessor, splits


def preprocess_cic_ids2018(sample_frac=None):
    """Preprocess CSE-CIC-IDS2018 dataset."""
    logger.info("=" * 60)
    logger.info("PREPROCESSING CSE-CIC-IDS2018")
    logger.info("=" * 60)

    # Load
    df = load_cic_ids2018(sample_frac=sample_frac)

    # Clean
    df = clean_dataframe(df, label_col="Label")

    # Class distribution
    dist = get_class_distribution(df, label_col="Label")
    logger.info(f"\nClass distribution:\n{dist.to_string(index=False)}")

    # Prepare features
    preprocessor = DataPreprocessor(dataset_name="cic_ids2018")
    X, y = preprocessor.prepare_features(df, remove_constant=True, remove_high_corr=False)

    # Fit and transform
    X_scaled, y_encoded = preprocessor.fit_transform(X, y)

    # Split
    splits = preprocessor.split_data(X_scaled, y_encoded)

    # Save
    preprocessor.save_artifacts()
    preprocessor.save_splits(splits)

    logger.info("CSE-CIC-IDS2018 preprocessing complete!")
    return preprocessor, splits


def main():
    parser = argparse.ArgumentParser(description="Preprocess IDS dataset")
    parser.add_argument(
        "--dataset",
        choices=["cicids2017", "cic_ids2018", "unsw_nb15", "all"],
        default="cic_ids2018",
        help="Dataset to preprocess (default: cic_ids2018)",
    )
    parser.add_argument(
        "--sample",
        type=float,
        default=None,
        help="Sample fraction for development (e.g., 0.1 for 10%%)",
    )
    args = parser.parse_args()

    if args.dataset in ("cic_ids2018", "all"):
        preprocess_cic_ids2018(sample_frac=args.sample)

    if args.dataset in ("cicids2017", "all"):
        preprocess_cicids2017(sample_frac=args.sample)

    if args.dataset in ("unsw_nb15", "all"):
        preprocess_unsw_nb15()


if __name__ == "__main__":
    main()
