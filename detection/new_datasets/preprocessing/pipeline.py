"""
Preprocessing Pipeline for new IoT / NetFlow datasets.

Handles:
  - Categorical encoding (LabelEncoder per column)
  - Numeric scaling (StandardScaler)
  - Stratified train / val / test splitting
  - Class balancing on training split only (SMOTE or class_weight)
  - Saving / loading fitted artifacts with joblib
  - Class distribution reporting before and after balancing
"""

import logging
from pathlib import Path
from typing import Tuple, Dict, Any, List, Optional

import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder

from detection.new_datasets.config import (
    RANDOM_STATE, TEST_SIZE, VAL_SIZE, DATA_MODELS,
)

logger = logging.getLogger(__name__)


class NewDatasetPreprocessor:
    """
    End-to-end preprocessing pipeline for any dataset that has already
    been loaded and label-mapped by one of the loaders.
    """

    def __init__(self, dataset_name: str):
        self.dataset_name = dataset_name
        self.scaler: Optional[StandardScaler] = None
        self.label_encoder: Optional[LabelEncoder] = None
        self.cat_encoders: Dict[str, LabelEncoder] = {}
        self.feature_names: List[str] = []
        self.save_dir = DATA_MODELS / dataset_name
        self.save_dir.mkdir(parents=True, exist_ok=True)

    # ── Feature / label separation ────────────────────────────────────────

    def prepare_features(
        self, df: pd.DataFrame
    ) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Separate features (X) and multi-class labels (y).
        Encode categoricals, drop metadata columns.

        Returns:
            (X, y) where X is all-numeric and y is the string label.
        """
        meta_cols = ["label", "label_binary", "label_original"]
        y = df["label"].copy()

        X = df.drop(columns=[c for c in meta_cols if c in df.columns],
                     errors="ignore")

        # ── Encode remaining categorical columns ──────────────────────────
        cat_cols = X.select_dtypes(include=["object", "category"]).columns.tolist()
        for col in cat_cols:
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col].astype(str))
            self.cat_encoders[col] = le
            logger.info(f"  Encoded categorical '{col}' → {len(le.classes_)} classes")

        # ── Remove constant columns ───────────────────────────────────────
        const_cols = [c for c in X.columns if X[c].nunique() <= 1]
        if const_cols:
            X.drop(columns=const_cols, inplace=True)
            logger.info(f"  Removed {len(const_cols)} constant columns")

        self.feature_names = X.columns.tolist()
        logger.info(f"  Feature matrix: {X.shape[0]:,} rows × {X.shape[1]} features")
        return X, y

    # ── Fit + transform ───────────────────────────────────────────────────

    def fit_transform(
        self, X: pd.DataFrame, y: pd.Series
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Fit scaler + label encoder, return transformed arrays."""
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(y)

        logger.info(f"  Classes: {list(self.label_encoder.classes_)}")
        return X_scaled, y_encoded

    def transform(
        self, X: pd.DataFrame, y: pd.Series
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Transform with already-fitted scaler + encoder."""
        # Ensure same feature columns
        for col in self.feature_names:
            if col not in X.columns:
                X[col] = 0
        X = X[self.feature_names]
        X_scaled = self.scaler.transform(X)
        y_encoded = self.label_encoder.transform(y)
        return X_scaled, y_encoded

    # ── Splitting ─────────────────────────────────────────────────────────

    def split_data(
        self, X: np.ndarray, y: np.ndarray
    ) -> Dict[str, np.ndarray]:
        """Stratified train / val / test split."""
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y,
            test_size=TEST_SIZE,
            random_state=RANDOM_STATE,
            stratify=y,
        )

        real_val = VAL_SIZE / (1 - TEST_SIZE)
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp,
            test_size=real_val,
            random_state=RANDOM_STATE,
            stratify=y_temp,
        )

        splits = {
            "X_train": X_train, "y_train": y_train,
            "X_val": X_val, "y_val": y_val,
            "X_test": X_test, "y_test": y_test,
        }
        logger.info(
            f"  Split sizes → train: {len(X_train):,}  "
            f"val: {len(X_val):,}  test: {len(X_test):,}"
        )
        return splits

    # ── Class balancing (train split only) ─────────────────────────────────

    def balance_train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        method: str = "smote",
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Balance training data.  method ∈ {'smote', 'none'}.
        Only the training split is resampled.
        """
        dist_before = pd.Series(y_train).value_counts().sort_index()
        logger.info(f"  Class distribution BEFORE balancing:\n{dist_before.to_string()}")

        if method == "smote":
            try:
                from imblearn.over_sampling import SMOTE
                # If any class has < 6 samples, use k_neighbors = min_count - 1
                min_count = dist_before.min()
                k = min(5, max(1, min_count - 1))
                sm = SMOTE(random_state=RANDOM_STATE, k_neighbors=k)
                X_train, y_train = sm.fit_resample(X_train, y_train)
                logger.info("  Applied SMOTE oversampling on training split")
            except Exception as e:
                logger.warning(f"  SMOTE failed ({e}), using original distribution")

        dist_after = pd.Series(y_train).value_counts().sort_index()
        logger.info(f"  Class distribution AFTER balancing:\n{dist_after.to_string()}")
        return X_train, y_train

    # ── Persistence ───────────────────────────────────────────────────────

    def save_artifacts(self) -> None:
        """Save scaler, label encoder, categorical encoders, feature names."""
        joblib.dump(self.scaler, self.save_dir / "scaler.joblib")
        joblib.dump(self.label_encoder, self.save_dir / "label_encoder.joblib")
        joblib.dump(self.cat_encoders, self.save_dir / "cat_encoders.joblib")
        joblib.dump(self.feature_names, self.save_dir / "feature_names.joblib")
        logger.info(f"  Artifacts saved to {self.save_dir}")

    def load_artifacts(self) -> None:
        """Load previously saved preprocessing artifacts."""
        self.scaler = joblib.load(self.save_dir / "scaler.joblib")
        self.label_encoder = joblib.load(self.save_dir / "label_encoder.joblib")
        self.cat_encoders = joblib.load(self.save_dir / "cat_encoders.joblib")
        self.feature_names = joblib.load(self.save_dir / "feature_names.joblib")
        logger.info(f"  Artifacts loaded from {self.save_dir}")

    def save_splits(self, splits: Dict[str, np.ndarray]) -> None:
        """Save train/val/test arrays."""
        for name, arr in splits.items():
            joblib.dump(arr, self.save_dir / f"{name}.joblib")

    def load_splits(self) -> Dict[str, np.ndarray]:
        """Load train/val/test arrays."""
        names = ["X_train", "y_train", "X_val", "y_val", "X_test", "y_test"]
        return {n: joblib.load(self.save_dir / f"{n}.joblib") for n in names}


def get_class_distribution(y, label_encoder=None) -> pd.DataFrame:
    """Pretty-print class distribution table."""
    if label_encoder is not None:
        labels = label_encoder.inverse_transform(y)
    else:
        labels = y
    dist = pd.Series(labels).value_counts().reset_index()
    dist.columns = ["Class", "Count"]
    dist["Percentage"] = (dist["Count"] / len(y) * 100).round(2)
    return dist
