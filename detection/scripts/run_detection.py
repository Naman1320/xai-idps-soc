#!/usr/bin/env python3
"""
Run the full detection pipeline on test data.

Loads a trained model, runs the full pipeline (classify → SHAP → MITRE → risk score),
produces alert JSON, and optionally forwards to the SOC backend.

Usage:
    python scripts/run_detection.py --model tuned_rf --dataset cicids2017
    python scripts/run_detection.py --model tuned_rf --dataset cicids2017 --forward
    python scripts/run_detection.py --model tuned_rf --dataset cicids2017 --limit 100
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import joblib
import numpy as np

from detection.pipeline import DetectionPipeline
from detection.pipeline.alert_forwarder import AlertForwarder
from detection.preprocessing.preprocessor import MODELS_DIR, DataPreprocessor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def load_model(model_name: str):
    """Load a trained model by name."""
    filepath = MODELS_DIR / f"{model_name}.joblib"
    if not filepath.exists():
        raise FileNotFoundError(
            f"Model not found: {filepath}\n"
            f"Run 'python scripts/train_model.py --model {model_name}' first."
        )

    data = joblib.load(filepath)

    # Handle different save formats
    if isinstance(data, dict) and "model" in data:
        return data["model"]
    return data


def main():
    parser = argparse.ArgumentParser(description="Run detection pipeline")
    parser.add_argument(
        "--model",
        choices=["baseline_rf", "tuned_rf", "xgboost"],
        default="tuned_rf",
        help="Model to use for detection",
    )
    parser.add_argument(
        "--dataset",
        choices=["cic_ids2018", "cicids2017", "unsw_nb15"],
        default="cic_ids2018",
        help="Dataset to run detection on (uses test split, default: cic_ids2018)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of flows to process (for quick testing)",
    )
    parser.add_argument(
        "--forward",
        action="store_true",
        help="Forward alerts to SOC backend",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Save alerts to JSON file",
    )
    parser.add_argument(
        "--no-geo",
        action="store_true",
        help="Disable MaxMind GeoLite2 enrichment",
    )
    parser.add_argument(
        "--no-threat-intel",
        action="store_true",
        help="Disable AbuseIPDB threat intelligence enrichment",
    )
    args = parser.parse_args()

    # Load preprocessor and data
    logger.info(f"Loading preprocessor for {args.dataset}...")
    preprocessor = DataPreprocessor(dataset_name=args.dataset)
    preprocessor.load_artifacts()
    splits = preprocessor.load_splits()

    X_test = splits["X_test"]
    y_test = splits["y_test"]

    if args.limit:
        X_test = X_test[: args.limit]
        y_test = y_test[: args.limit]

    logger.info(f"Test set: {len(X_test)} flows")

    # Load model
    logger.info(f"Loading model: {args.model}...")
    model = load_model(args.model)

    # Initialize pipeline with geo & threat intel
    pipeline = DetectionPipeline(
        model=model,
        preprocessor=preprocessor,
        model_name=args.model,
        shap_top_n=10,
        enable_geo=not args.no_geo,
        enable_threat_intel=not args.no_threat_intel,
    )

    # Generate synthetic IPs for demo (since datasets don't include IPs after preprocessing)
    np.random.seed(42)
    source_ips = [
        f"192.168.1.{np.random.randint(100, 200)}" for _ in range(len(X_test))
    ]
    dest_ips = [f"192.168.1.{np.random.randint(1, 20)}" for _ in range(len(X_test))]
    dest_ports = [
        np.random.choice([22, 80, 443, 3306, 8080]) for _ in range(len(X_test))
    ]

    # Run pipeline
    logger.info("Running detection pipeline...")
    start_time = time.time()

    alerts = pipeline.process_flows(
        X_scaled=X_test,
        source_ips=source_ips,
        dest_ips=dest_ips,
        dest_ports=dest_ports,
    )

    elapsed = time.time() - start_time
    logger.info("\nPipeline results:")
    logger.info(f"  Flows processed: {len(X_test)}")
    logger.info(f"  Alerts generated: {len(alerts)}")
    logger.info(f"  Total time: {elapsed:.2f}s")
    logger.info(f"  Throughput: {len(X_test) / max(elapsed, 0.001):.0f} flows/sec")

    # Show sample alerts
    if alerts:
        logger.info("\n--- Sample Alert ---")
        sample = alerts[0]
        logger.info(f"  Attack: {sample['classification']['attack_class']}")
        logger.info(f"  Confidence: {sample['classification']['confidence']:.3f}")
        logger.info(
            f"  Risk Score: {sample['risk_score']['composite']:.3f} ({sample['risk_score']['severity']})"
        )
        logger.info(
            f"  MITRE: {sample['mitre_mapping']['technique_id']} - {sample['mitre_mapping']['technique_name']}"
        )

        # Display Geo context if present
        if "geo_context" in sample and "source" in sample["geo_context"]:
            geo_src = sample["geo_context"]["source"]
            logger.info(
                f"  Geo Source: {geo_src.get('city')}, {geo_src.get('country')} (ASN {geo_src.get('asn')} - {geo_src.get('asn_org')})"
            )

        # Display Threat Intel if present
        if "threat_intel" in sample and "source_ip" in sample["threat_intel"]:
            ti = sample["threat_intel"]["source_ip"]
            logger.info(
                f"  Threat Intel: Abuse Score {ti.get('abuse_confidence_score')} | Known Bad: {ti.get('is_known_bad')} (Provider: {ti.get('provider')})"
            )

        logger.info("  Top SHAP features:")
        for feat in sample["shap_explanation"]["feature_contributions"][:3]:
            logger.info(
                f"    {feat['feature']}: SHAP={feat['shap_value']:.4f} (value={feat['feature_value']:.4f})"
            )

    # Save alerts to file
    if args.output:
        output_path = Path(args.output)
        with open(output_path, "w") as f:
            json.dump(alerts, f, indent=2, default=str)
        logger.info(f"\nAlerts saved to {output_path}")

    # Forward to SOC backend
    if args.forward and alerts:
        logger.info(f"\nForwarding {len(alerts)} alerts to SOC backend...")
        forwarder = AlertForwarder()
        result = forwarder.send_batch(alerts)
        logger.info(f"Forwarding result: {result}")


if __name__ == "__main__":
    main()
