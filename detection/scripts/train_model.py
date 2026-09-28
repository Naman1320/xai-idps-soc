#!/usr/bin/env python3
"""
Train ML models for intrusion detection.

Usage:
    python scripts/train_model.py --model baseline --dataset cicids2017
    python scripts/train_model.py --model rf_tuned --dataset cicids2017
    python scripts/train_model.py --model xgboost --dataset cicids2017
    python scripts/train_model.py --model all --dataset cicids2017
    python scripts/train_model.py --model rf_tuned --dataset cicids2017 --quick  # Skip hyperparameter search
"""

import argparse
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from detection.preprocessing.preprocessor import DataPreprocessor
from detection.models.baseline import BaselineModel
from detection.models.random_forest import TunedRandomForest
from detection.models.xgboost_model import XGBoostModel
from detection.models.evaluator import ModelEvaluator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def train_and_evaluate(model_class, model_name, splits, class_names, quick=False):
    """Train a model and evaluate on validation set."""
    logger.info(f"\n{'='*60}")
    logger.info(f"TRAINING: {model_name}")
    logger.info(f"{'='*60}")

    X_train = splits["X_train"]
    y_train = splits["y_train"]
    X_val = splits["X_val"]
    y_val = splits["y_val"]

    model_instance = model_class()
    start_time = time.time()

    if model_name == "baseline_rf":
        model_instance.train(X_train, y_train)
    elif quick:
        # Use default good params, skip search
        model_instance.train_with_params(X_train, y_train)
    else:
        # Full hyperparameter search
        result = model_instance.train(X_train, y_train, n_iter=20, cv=3)
        logger.info(f"Search result: {result}")

    train_time = time.time() - start_time
    logger.info(f"Training time: {train_time:.1f}s")

    # Evaluate on validation set
    y_pred = model_instance.predict(X_val)
    y_proba = model_instance.predict_proba(X_val)

    evaluator = ModelEvaluator(class_names=class_names)
    results = evaluator.evaluate(y_val, y_pred, y_proba, model_name=model_name)

    # Print per-class metrics
    report_df = evaluator.get_report_dataframe(model_name)
    logger.info(f"\nPer-class metrics (validation set):\n{report_df.to_string(index=False)}")

    # Save model
    model_instance.save()
    logger.info(f"Model saved as {model_instance.name}.joblib")

    return model_instance, results


def main():
    parser = argparse.ArgumentParser(description="Train IDS ML models")
    parser.add_argument(
        "--model",
        choices=["baseline", "rf_tuned", "xgboost", "all"],
        default="all",
        help="Model to train",
    )
    parser.add_argument(
        "--dataset",
        choices=["cicids2017", "unsw_nb15"],
        default="cicids2017",
        help="Dataset to use",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Skip hyperparameter search (use default good params)",
    )
    args = parser.parse_args()

    # Load preprocessed data
    preprocessor = DataPreprocessor(dataset_name=args.dataset)
    preprocessor.load_artifacts()
    splits = preprocessor.load_splits()

    class_names = list(preprocessor.label_encoder.classes_)
    logger.info(f"Dataset: {args.dataset}")
    logger.info(f"Classes: {class_names}")
    logger.info(f"Training samples: {len(splits['X_train'])}")
    logger.info(f"Validation samples: {len(splits['X_val'])}")

    models_to_train = []
    if args.model in ("baseline", "all"):
        models_to_train.append((BaselineModel, "baseline_rf"))
    if args.model in ("rf_tuned", "all"):
        models_to_train.append((TunedRandomForest, "tuned_rf"))
    if args.model in ("xgboost", "all"):
        models_to_train.append((XGBoostModel, "xgboost"))

    all_results = {}
    for model_class, model_name in models_to_train:
        _, results = train_and_evaluate(
            model_class, model_name, splits, class_names, quick=args.quick
        )
        all_results[model_name] = results

    # Compare models
    if len(all_results) > 1:
        evaluator = ModelEvaluator(class_names=class_names)
        evaluator.results = all_results
        comparison = evaluator.compare_models()
        logger.info(f"\n{'='*60}")
        logger.info("MODEL COMPARISON (Validation Set)")
        logger.info(f"{'='*60}")
        logger.info(f"\n{comparison.to_string(index=False)}")


if __name__ == "__main__":
    main()
