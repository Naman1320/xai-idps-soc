"""
Preprocessor: Feature selection, normalization, and train/test splitting.

Handles:
- Removing non-numeric and identifier columns
- Feature selection via correlation and importance analysis
- StandardScaler normalization
- Stratified train/validation/test splitting
- Saving/loading preprocessing artifacts
"""

import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent
PROCESSED_DATA_DIR = PROJECT_ROOT / "data" / "processed"
MODELS_DIR = PROJECT_ROOT / "data" / "models"

# Columns to always drop (identifiers, not features)
COLUMNS_TO_DROP_CICIDS = [
    "Flow ID",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "Timestamp",
    "Label",
    # Also drop these if they exist with spaces
    " Flow ID",
    " Source IP",
    " Source Port",
    " Destination IP",
    " Destination Port",
    " Timestamp",
]

# Columns to always drop from UNSW-NB15
COLUMNS_TO_DROP_UNSW = [
    "id",
    "label",
    "attack_cat",
    "srcip",
    "sport",
    "dstip",
    "dsport",
]

# Columns to always drop from CSE-CIC-IDS2018
COLUMNS_TO_DROP_CIC_IDS2018 = [
    "Dst Port",
    "Timestamp",
    "Label",
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
    "Destination Port",
    "Source IP",
    "Source Port",
]


class DataPreprocessor:
    """
    Preprocesses IDS datasets for ML training and inference.

    Performs:
    1. Column dropping (identifiers, non-features)
    2. Constant/near-constant feature removal
    3. High-correlation feature removal (optional)
    4. StandardScaler normalization
    5. Label encoding
    6. Stratified splitting

    All artifacts (scaler, label_encoder, feature_names) are saved for
    reproducible inference in the detection pipeline.
    """

    def __init__(self, dataset_name: str = "cicids2017"):
        """
        Args:
            dataset_name: 'cicids2017', 'cic_ids2018' (or 'cse_cic_ids2018'), or 'unsw_nb15'.
        """
        self.dataset_name = dataset_name
        self.scaler: StandardScaler | None = None
        self.label_encoder: LabelEncoder | None = None
        self.feature_names: list[str] = []
        self.label_col: str = (
            "Label"
            if dataset_name in ("cicids2017", "cic_ids2018", "cse_cic_ids2018")
            else "attack_cat"
        )
        if dataset_name in ("cic_ids2018", "cse_cic_ids2018"):
            self.columns_to_drop = COLUMNS_TO_DROP_CIC_IDS2018
        elif dataset_name == "cicids2017":
            self.columns_to_drop = COLUMNS_TO_DROP_CICIDS
        else:
            self.columns_to_drop = COLUMNS_TO_DROP_UNSW

    def prepare_features(
        self,
        df: pd.DataFrame,
        remove_constant: bool = True,
        remove_high_corr: bool = False,
        corr_threshold: float = 0.95,
    ) -> tuple[pd.DataFrame, pd.Series]:
        """
        Extract features (X) and labels (y) from raw DataFrame.

        Args:
            df: Cleaned DataFrame with label column.
            remove_constant: Remove features with zero or near-zero variance.
            remove_high_corr: Remove one of each pair of highly correlated features.
            corr_threshold: Correlation threshold for removal.

        Returns:
            Tuple of (X features DataFrame, y labels Series).
        """
        # Extract labels
        if self.label_col not in df.columns:
            raise ValueError(f"Label column '{self.label_col}' not found in DataFrame")
        y = df[self.label_col].copy()

        # Drop identifier and label columns
        drop_cols = [c for c in self.columns_to_drop if c in df.columns]
        X = df.drop(columns=drop_cols, errors="ignore")

        # Keep only numeric columns
        X = X.select_dtypes(include=[np.number])

        # Remove constant or near-constant features
        if remove_constant:
            variance = X.var()
            constant_cols = variance[variance < 1e-10].index.tolist()
            if constant_cols:
                logger.info(
                    f"Removing {len(constant_cols)} constant/near-constant features: {constant_cols[:5]}..."
                )
                X = X.drop(columns=constant_cols)

        # Remove highly correlated features (optional, can be slow for large datasets)
        if remove_high_corr:
            corr_matrix = X.corr().abs()
            upper = corr_matrix.where(
                np.triu(np.ones(corr_matrix.shape), k=1).astype(bool)
            )
            high_corr_cols = [
                col for col in upper.columns if any(upper[col] > corr_threshold)
            ]
            if high_corr_cols:
                logger.info(
                    f"Removing {len(high_corr_cols)} highly correlated features "
                    f"(threshold={corr_threshold}): {high_corr_cols[:5]}..."
                )
                X = X.drop(columns=high_corr_cols)

        self.feature_names = X.columns.tolist()
        logger.info(f"Final feature count: {len(self.feature_names)}")

        return X, y

    def fit_transform(
        self, X: pd.DataFrame, y: pd.Series
    ) -> tuple[np.ndarray, np.ndarray]:
        """
        Fit scaler and label encoder on training data, then transform.

        Args:
            X: Feature DataFrame.
            y: Label Series.

        Returns:
            Tuple of (X_scaled numpy array, y_encoded numpy array).
        """
        # Fit and transform scaler
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Fit and transform label encoder
        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(y)

        logger.info(f"Classes: {list(self.label_encoder.classes_)}")
        logger.info(f"Scaled feature shape: {X_scaled.shape}")

        return X_scaled, y_encoded

    def transform(self, X: pd.DataFrame, y: pd.Series) -> tuple[np.ndarray, np.ndarray]:
        """
        Transform using already-fitted scaler and label encoder.

        Args:
            X: Feature DataFrame (must have same columns as training data).
            y: Label Series.

        Returns:
            Tuple of (X_scaled, y_encoded).
        """
        if self.scaler is None or self.label_encoder is None:
            raise RuntimeError("Preprocessor not fitted. Call fit_transform first.")

        # Ensure same feature columns in same order
        missing = set(self.feature_names) - set(X.columns)
        extra = set(X.columns) - set(self.feature_names)
        if missing:
            logger.warning(f"Missing features (filling with 0): {missing}")
            for col in missing:
                X[col] = 0
        if extra:
            X = X.drop(columns=list(extra))
        X = X[self.feature_names]

        X_scaled = self.scaler.transform(X)
        y_encoded = self.label_encoder.transform(y)

        return X_scaled, y_encoded

    def split_data(
        self,
        X: np.ndarray,
        y: np.ndarray,
        test_size: float = 0.15,
        val_size: float = 0.15,
        random_state: int = 42,
    ) -> dict[str, np.ndarray]:
        """
        Stratified split into train/validation/test sets.

        Args:
            X: Feature array.
            y: Label array.
            test_size: Fraction for test set.
            val_size: Fraction for validation set.
            random_state: Random seed for reproducibility.

        Returns:
            Dict with keys: X_train, X_val, X_test, y_train, y_val, y_test.
        """
        # First split: train+val vs test
        X_temp, X_test, y_temp, y_test = train_test_split(
            X,
            y,
            test_size=test_size,
            random_state=random_state,
            stratify=y,
        )

        # Second split: train vs val (adjust val_size relative to remaining data)
        val_relative = val_size / (1 - test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp,
            y_temp,
            test_size=val_relative,
            random_state=random_state,
            stratify=y_temp,
        )

        logger.info(
            f"Split: train={len(X_train)}, val={len(X_val)}, test={len(X_test)} "
            f"({len(X_train) / len(X) * 100:.1f}%/{len(X_val) / len(X) * 100:.1f}%/{len(X_test) / len(X) * 100:.1f}%)"
        )

        return {
            "X_train": X_train,
            "y_train": y_train,
            "X_val": X_val,
            "y_val": y_val,
            "X_test": X_test,
            "y_test": y_test,
        }

    def save_artifacts(self, output_dir: Path | None = None) -> None:
        """Save preprocessing artifacts (scaler, label_encoder, feature_names)."""
        if output_dir is None:
            output_dir = PROCESSED_DATA_DIR / self.dataset_name
        output_dir.mkdir(parents=True, exist_ok=True)

        joblib.dump(self.scaler, output_dir / "scaler.joblib")
        joblib.dump(self.label_encoder, output_dir / "label_encoder.joblib")
        joblib.dump(self.feature_names, output_dir / "feature_names.joblib")

        logger.info(f"Preprocessing artifacts saved to {output_dir}")

    def load_artifacts(self, input_dir: Path | None = None) -> None:
        """Load preprocessing artifacts."""
        if input_dir is None:
            input_dir = PROCESSED_DATA_DIR / self.dataset_name

        self.scaler = joblib.load(input_dir / "scaler.joblib")
        self.label_encoder = joblib.load(input_dir / "label_encoder.joblib")
        self.feature_names = joblib.load(input_dir / "feature_names.joblib")

        logger.info(f"Preprocessing artifacts loaded from {input_dir}")

    def save_splits(
        self, splits: dict[str, np.ndarray], output_dir: Path | None = None
    ) -> None:
        """Save train/val/test splits as .npy files."""
        if output_dir is None:
            output_dir = PROCESSED_DATA_DIR / self.dataset_name
        output_dir.mkdir(parents=True, exist_ok=True)

        for name, array in splits.items():
            np.save(output_dir / f"{name}.npy", array)
            logger.info(f"Saved {name}: shape={array.shape}")

    def load_splits(self, input_dir: Path | None = None) -> dict[str, np.ndarray]:
        """Load train/val/test splits from .npy files."""
        if input_dir is None:
            input_dir = PROCESSED_DATA_DIR / self.dataset_name

        splits = {}
        for name in ["X_train", "y_train", "X_val", "y_val", "X_test", "y_test"]:
            filepath = input_dir / f"{name}.npy"
            if filepath.exists():
                splits[name] = np.load(filepath)
                logger.info(f"Loaded {name}: shape={splits[name].shape}")
            else:
                raise FileNotFoundError(f"Split file not found: {filepath}")

        return splits
