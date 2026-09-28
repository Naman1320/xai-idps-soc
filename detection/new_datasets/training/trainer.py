"""
Model Trainer for new IoT / NetFlow datasets.

Models per dataset:
  1. Random Forest  (with light hyperparameter tuning)
  2. XGBoost        (GPU optional, with early stopping)
  3. MLP baseline   (sklearn MLPClassifier)

All models are saved to  models/new/<dataset>/<dataset>_<model>.joblib
"""

import logging
import time
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import RandomizedSearchCV
import xgboost as xgb

from detection.new_datasets.config import RANDOM_STATE, DATA_MODELS

logger = logging.getLogger(__name__)

# ── Hyperparameter search spaces (light tuning) ──────────────────────────────
RF_PARAM_GRID = {
    "n_estimators": [100, 200, 300],
    "max_depth": [15, 25, None],
    "min_samples_split": [2, 5],
    "min_samples_leaf": [1, 2],
    "max_features": ["sqrt", "log2"],
}

XGB_PARAMS = {
    "n_estimators": 300,
    "max_depth": 8,
    "learning_rate": 0.1,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "min_child_weight": 3,
    "reg_alpha": 0.1,
    "reg_lambda": 1.0,
    "random_state": RANDOM_STATE,
    "n_jobs": -1,
    "eval_metric": "mlogloss",
    "early_stopping_rounds": 15,
}

MLP_PARAMS = {
    "hidden_layer_sizes": (128, 64),
    "activation": "relu",
    "solver": "adam",
    "learning_rate": "adaptive",
    "learning_rate_init": 0.001,
    "max_iter": 200,
    "early_stopping": True,
    "validation_fraction": 0.1,
    "random_state": RANDOM_STATE,
}


def train_random_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    dataset_name: str,
    n_iter: int = 8,
) -> RandomForestClassifier:
    """Train RF with RandomizedSearchCV."""
    logger.info(f"[{dataset_name}] Training Random Forest (tuning {n_iter} combos)...")
    t0 = time.time()

    rf = RandomForestClassifier(
        random_state=RANDOM_STATE,
        n_jobs=-1,
        class_weight="balanced_subsample",
    )
    search = RandomizedSearchCV(
        rf, RF_PARAM_GRID,
        n_iter=n_iter,
        cv=3,
        scoring="f1_macro",
        random_state=RANDOM_STATE,
        n_jobs=-1,
        verbose=0,
    )
    search.fit(X_train, y_train)

    best = search.best_estimator_
    elapsed = time.time() - t0
    logger.info(f"  RF best params: {search.best_params_}")
    logger.info(f"  RF best CV F1-macro: {search.best_score_:.4f}  ({elapsed:.1f}s)")

    _save_model(best, dataset_name, "random_forest")
    return best


def train_xgboost(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    dataset_name: str,
    num_classes: int = 2,
) -> xgb.XGBClassifier:
    """Train XGBoost with early stopping on the validation set."""
    logger.info(f"[{dataset_name}] Training XGBoost (early stopping)...")
    t0 = time.time()

    params = dict(XGB_PARAMS)
    if num_classes <= 2:
        params["objective"] = "binary:logistic"
        params["eval_metric"] = "logloss"
    else:
        params["objective"] = "multi:softprob"
        params["num_class"] = num_classes

    model = xgb.XGBClassifier(**params)
    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=False,
    )

    elapsed = time.time() - t0
    logger.info(f"  XGBoost trained in {elapsed:.1f}s  "
                f"(best iteration: {model.best_iteration})")

    _save_model(model, dataset_name, "xgboost")
    return model


def train_mlp(
    X_train: np.ndarray,
    y_train: np.ndarray,
    dataset_name: str,
) -> MLPClassifier:
    """Train MLP baseline."""
    logger.info(f"[{dataset_name}] Training MLP baseline...")
    t0 = time.time()

    model = MLPClassifier(**MLP_PARAMS)
    model.fit(X_train, y_train)

    elapsed = time.time() - t0
    logger.info(f"  MLP trained in {elapsed:.1f}s  (loss: {model.loss_:.4f})")

    _save_model(model, dataset_name, "mlp")
    return model


def train_all_models(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    dataset_name: str,
    num_classes: int = 2,
) -> Dict[str, Any]:
    """Train all three model architectures and return them."""
    models = {}
    models["random_forest"] = train_random_forest(X_train, y_train, dataset_name)
    models["xgboost"] = train_xgboost(
        X_train, y_train, X_val, y_val, dataset_name, num_classes
    )
    models["mlp"] = train_mlp(X_train, y_train, dataset_name)
    return models


def _save_model(model: Any, dataset_name: str, model_name: str) -> Path:
    """Save model to  models/new/<dataset>/<dataset>_<model>.joblib"""
    save_dir = DATA_MODELS / dataset_name
    save_dir.mkdir(parents=True, exist_ok=True)
    path = save_dir / f"{dataset_name}_{model_name}.joblib"
    joblib.dump(model, path)
    logger.info(f"  Model saved: {path}")
    return path


def load_model(dataset_name: str, model_name: str) -> Any:
    """Load a previously saved model."""
    path = DATA_MODELS / dataset_name / f"{dataset_name}_{model_name}.joblib"
    return joblib.load(path)
