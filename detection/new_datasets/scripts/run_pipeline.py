#!/usr/bin/env python3
"""
Master Pipeline Script for New IoT / NetFlow Datasets.

Usage:
    # Run full pipeline for all three datasets
    python -m detection.new_datasets.scripts.run_pipeline --all

    # Run for a single dataset
    python -m detection.new_datasets.scripts.run_pipeline --dataset ciciot2023

    # Run only cross-dataset generalization tests
    python -m detection.new_datasets.scripts.run_pipeline --cross-only

    # Run with XAI explanations
    python -m detection.new_datasets.scripts.run_pipeline --all --explain
"""

import argparse
import logging
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

import numpy as np
import pandas as pd

from detection.new_datasets.config import DATASET_REGISTRY, DATA_MODELS, DATA_RESULTS
from detection.new_datasets.preprocessing.pipeline import (
    NewDatasetPreprocessor, get_class_distribution,
)
from detection.new_datasets.training.trainer import train_all_models
from detection.new_datasets.evaluation.evaluator import (
    evaluate_all_models, build_comparison_table, print_confusion_matrix,
)
from detection.new_datasets.cross_dataset.generalization import (
    run_all_cross_tests, build_cross_table,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("pipeline")


def load_dataset(name: str) -> pd.DataFrame:
    """Dynamically load a dataset using its registered loader."""
    cfg = DATASET_REGISTRY[name]
    sample_frac = cfg["sample_frac"]

    if name == "ciciot2023":
        from detection.new_datasets.loaders.ciciot2023 import load_ciciot2023
        return load_ciciot2023(sample_frac=sample_frac)
    elif name == "edge_iiotset":
        from detection.new_datasets.loaders.edge_iiotset import load_edge_iiotset
        return load_edge_iiotset(sample_frac=sample_frac)
    elif name == "nf_ton_iot_v3":
        from detection.new_datasets.loaders.nf_ton_iot_v3 import load_nf_ton_iot_v3
        return load_nf_ton_iot_v3(sample_frac=sample_frac)
    else:
        raise ValueError(f"Unknown dataset: {name}")


def run_single_dataset(name: str, do_explain: bool = False) -> dict:
    """
    Full pipeline for one dataset:
      Load → Preprocess → Split → Balance → Train → Evaluate → (Explain)
    """
    logger.info(f"\n{'='*70}")
    logger.info(f"  PIPELINE: {DATASET_REGISTRY[name]['display_name']}")
    logger.info(f"{'='*70}")

    t0 = time.time()

    # 1. Load
    logger.info("Step 1: Loading dataset...")
    df = load_dataset(name)

    # Show label mapping
    logger.info("\nLabel Mapping (raw → unified):")
    mapping = df[["label_original", "label"]].drop_duplicates().sort_values("label")
    for _, row in mapping.iterrows():
        logger.info(f"  {row['label_original']:30s} → {row['label']}")

    # 2. Preprocess
    logger.info("\nStep 2: Preprocessing...")
    preprocessor = NewDatasetPreprocessor(name)
    X, y = preprocessor.prepare_features(df)

    # Show class distribution
    logger.info("\nClass Distribution (before split):")
    dist = y.value_counts()
    for cls, count in dist.items():
        logger.info(f"  {cls:20s}: {count:>8,} ({count/len(y)*100:.1f}%)")

    X_scaled, y_encoded = preprocessor.fit_transform(X, y)
    num_classes = len(preprocessor.label_encoder.classes_)

    # 3. Split
    logger.info("\nStep 3: Train/Val/Test split...")
    splits = preprocessor.split_data(X_scaled, y_encoded)

    # 4. Balance training split
    logger.info("\nStep 4: Balancing training split (SMOTE)...")
    X_train_bal, y_train_bal = preprocessor.balance_train(
        splits["X_train"], splits["y_train"], method="smote"
    )

    # Save artifacts
    preprocessor.save_artifacts()
    preprocessor.save_splits(splits)

    # 5. Train all models
    logger.info("\nStep 5: Training models...")
    models = train_all_models(
        X_train_bal, y_train_bal,
        splits["X_val"], splits["y_val"],
        name, num_classes,
    )

    # 6. Evaluate
    logger.info("\nStep 6: Evaluation on test set...")
    results = evaluate_all_models(
        models, splits["X_test"], splits["y_test"],
        name, preprocessor.label_encoder,
    )

    # Print confusion matrices
    for r in results:
        cm_str = print_confusion_matrix(
            r["confusion_matrix"],
            [str(c) for c in preprocessor.label_encoder.classes_],
            name, r["model"],
        )
        logger.info(cm_str)

    # 7. XAI (optional)
    if do_explain:
        logger.info("\nStep 7: XAI Explanations...")
        _run_explanations(
            models, splits, preprocessor, name
        )

    elapsed = time.time() - t0
    logger.info(f"\n✅ Pipeline complete for {name} in {elapsed:.1f}s")

    return {
        "name": name,
        "results": results,
        "preprocessor": preprocessor,
        "models": models,
        "df": df,
    }


def _run_explanations(models, splits, preprocessor, name):
    """Run SHAP and LIME explanations on the best model."""
    from detection.new_datasets.explainability.explainer import (
        compute_shap_global, explain_alert,
    )

    # Use the best model (highest F1)
    best_model_name = "random_forest"  # usually best for tree-based
    model = models[best_model_name]

    # Global SHAP
    shap_result = compute_shap_global(
        model, splits["X_test"],
        preprocessor.feature_names, name,
    )

    # Local explanation for 3 random attack samples
    attack_idx = np.where(splits["y_test"] != 0)[0]
    if len(attack_idx) > 0:
        sample_idx = np.random.RandomState(42).choice(
            attack_idx, min(3, len(attack_idx)), replace=False
        )
        for i, idx in enumerate(sample_idx):
            result = explain_alert(
                model, splits["X_test"][idx],
                preprocessor.feature_names,
                preprocessor.label_encoder,
                name,
            )
            logger.info(f"\n--- Alert Explanation #{i+1} ---")
            logger.info(result["plain_english"])


def run_cross_dataset_tests(all_data: dict) -> pd.DataFrame:
    """Run cross-dataset generalization tests."""
    logger.info(f"\n{'='*70}")
    logger.info("  CROSS-DATASET GENERALIZATION TESTS")
    logger.info(f"{'='*70}")

    results = run_all_cross_tests(all_data)
    table = build_cross_table(results)

    logger.info("\nCross-Dataset Results:")
    logger.info(f"\n{table.to_string(index=False)}")
    return table


def main():
    parser = argparse.ArgumentParser(
        description="Run the new-datasets ML pipeline"
    )
    parser.add_argument(
        "--dataset", type=str, default=None,
        choices=list(DATASET_REGISTRY.keys()),
        help="Single dataset to process",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Process all three datasets",
    )
    parser.add_argument(
        "--cross-only", action="store_true",
        help="Run only cross-dataset generalization tests",
    )
    parser.add_argument(
        "--explain", action="store_true",
        help="Run XAI explanations (SHAP + LIME)",
    )
    parser.add_argument(
        "--no-balance", action="store_true",
        help="Skip SMOTE balancing",
    )
    args = parser.parse_args()

    if not args.dataset and not args.all and not args.cross_only:
        parser.print_help()
        sys.exit(1)

    DATA_RESULTS.mkdir(parents=True, exist_ok=True)

    all_results = []
    all_data = {}  # for cross-dataset tests

    if args.all:
        datasets_to_run = list(DATASET_REGISTRY.keys())
    elif args.dataset:
        datasets_to_run = [args.dataset]
    else:
        datasets_to_run = []

    for name in datasets_to_run:
        try:
            out = run_single_dataset(name, do_explain=args.explain)
            all_results.extend(out["results"])
            all_data[name] = out["df"]
        except FileNotFoundError as e:
            logger.error(f"\n⚠️  {e}")
            logger.error(f"Skipping {name}.\n")

    # Comparison table
    if all_results:
        table = build_comparison_table(all_results)
        logger.info(f"\n{'='*70}")
        logger.info("  COMBINED RESULTS COMPARISON TABLE")
        logger.info(f"{'='*70}")
        logger.info(f"\n{table.to_string(index=False)}")

        # Save to CSV
        csv_path = DATA_RESULTS / "comparison_table.csv"
        table.to_csv(csv_path, index=False)
        logger.info(f"\nResults saved to {csv_path}")

    # Cross-dataset tests
    if (args.all or args.cross_only) and len(all_data) >= 2:
        cross_table = run_cross_dataset_tests(all_data)
        cross_path = DATA_RESULTS / "cross_dataset_results.csv"
        cross_table.to_csv(cross_path, index=False)
        logger.info(f"Cross-dataset results saved to {cross_path}")

    logger.info("\n🏁 Pipeline finished.")


if __name__ == "__main__":
    main()
