"""
Detection Pipeline: End-to-end flow from features → classify → explain → enrich → alert JSON.

This is the core integration module that connects all detection-side components:
1. Load trained model and preprocessing artifacts
2. Classify input flows
3. Generate SHAP explanations for alerts
4. Map to MITRE ATT&CK techniques
5. Compute asset criticality
6. Geolocation enrichment (MaxMind GeoLite2)
7. Threat intelligence lookup (AbuseIPDB)
8. Compute composite risk scores (4-weight formula including threat-intel)
9. Produce structured alert JSON ready for SOC backend ingestion
"""

import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

from detection.enrichment.asset_context import AssetContext
from detection.enrichment.geo_enricher import GeoEnricher
from detection.enrichment.mitre_mapper import MitreMapper
from detection.enrichment.risk_scorer import RiskScorer
from detection.enrichment.threat_intel import ThreatIntelEnricher
from detection.explainability import ShapExplainer
from detection.preprocessing.preprocessor import DataPreprocessor

logger = logging.getLogger(__name__)


class DetectionPipeline:
    """
    End-to-end detection pipeline.

    Connects: Model → SHAP → MITRE → Asset Context → Geo → Threat-Intel → Risk Score → Alert JSON

    This pipeline is the integration contribution of the project.
    Each alert it produces carries:
    - ML classification + confidence
    - SHAP feature-importance explanation
    - MITRE ATT&CK technique mapping
    - Geolocation context (country/region/city/ASN)
    - Threat intelligence reputation score
    - Composite risk score with transparent 4-weight breakdown
    """

    def __init__(
        self,
        model,
        preprocessor: DataPreprocessor,
        model_name: str = "model",
        shap_top_n: int = 10,
        enable_geo: bool = True,
        enable_threat_intel: bool = True,
    ):
        """
        Args:
            model: A fitted sklearn/xgboost model with predict() and predict_proba().
            preprocessor: Fitted DataPreprocessor with scaler and label_encoder.
            model_name: Name of the model (for logging/metadata).
            shap_top_n: Number of top SHAP features per alert.
            enable_geo: Enable geolocation enrichment (requires GeoLite2 .mmdb files).
            enable_threat_intel: Enable threat-intel enrichment (requires AbuseIPDB API key).
        """
        self.model = model
        self.preprocessor = preprocessor
        self.model_name = model_name
        self.shap_top_n = shap_top_n

        # Initialize SHAP explainer
        self.shap_explainer = ShapExplainer(
            model=model,
            feature_names=preprocessor.feature_names,
        )

        # Initialize enrichment modules
        self.mitre_mapper = MitreMapper()
        self.asset_context = AssetContext()
        self.risk_scorer = RiskScorer()

        # Initialize geo enrichment (gracefully degrades if .mmdb files missing)
        self.geo_enricher = None
        if enable_geo:
            try:
                self.geo_enricher = GeoEnricher()
                logger.info("Geolocation enrichment enabled")
            except Exception as e:
                logger.warning(f"Geolocation enrichment disabled: {e}")

        # Initialize threat-intel enrichment (gracefully degrades if no API key)
        self.threat_intel = None
        if enable_threat_intel:
            try:
                self.threat_intel = ThreatIntelEnricher()
                logger.info("Threat intelligence enrichment enabled")
            except Exception as e:
                logger.warning(f"Threat intelligence enrichment disabled: {e}")

        logger.info(f"Detection pipeline initialized with model '{model_name}'")

    def process_flows(
        self,
        X_scaled: np.ndarray,
        source_ips: list[str] | None = None,
        dest_ips: list[str] | None = None,
        dest_ports: list[int] | None = None,
        protocols: list[str] | None = None,
        flow_features_raw: list[dict] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Process a batch of network flows through the full pipeline.

        Args:
            X_scaled: Scaled feature matrix (n_samples, n_features).
            source_ips: Source IPs for each flow (or None for synthetic/dataset data).
            dest_ips: Destination IPs for each flow.
            dest_ports: Destination ports for each flow.
            protocols: Protocols for each flow.
            flow_features_raw: Raw (unscaled) feature dicts for reference.

        Returns:
            List of alert dicts (only for flows classified as attacks above threshold).
        """
        start_time = time.time()
        n_flows = len(X_scaled)

        # Step 1: Classify
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)

        # Decode class labels
        class_labels = self.preprocessor.label_encoder.inverse_transform(predictions)
        class_names = list(self.preprocessor.label_encoder.classes_)

        alerts = []

        for i in range(n_flows):
            attack_class = class_labels[i]

            # Skip benign flows
            if attack_class.lower() in ("benign", "normal"):
                continue

            # Get ML confidence (probability of predicted class)
            ml_confidence = float(probabilities[i][predictions[i]])

            # Check minimum confidence threshold
            if ml_confidence < self.risk_scorer.min_ml_confidence:
                continue

            # Step 2: SHAP explanation
            shap_explanation = self.shap_explainer.explain_single(
                X_scaled[i], int(predictions[i]), top_n=self.shap_top_n
            )

            # Step 3: MITRE ATT&CK mapping
            mitre_info = self.mitre_mapper.map(attack_class)

            # Step 4: Asset criticality
            dest_ip = dest_ips[i] if dest_ips and i < len(dest_ips) else "unknown"
            asset_criticality = self.asset_context.get_criticality(dest_ip)

            # Step 5: Geolocation enrichment
            source_ip = (
                source_ips[i] if source_ips and i < len(source_ips) else "unknown"
            )
            geo_source = None
            geo_dest = None
            if self.geo_enricher:
                geo_source = self.geo_enricher.enrich(source_ip)
                geo_dest = self.geo_enricher.enrich(dest_ip)

            # Step 6: Threat intelligence lookup
            threat_intel_result = None
            threat_intel_score = 0.0
            if self.threat_intel:
                threat_intel_result = self.threat_intel.check_ip(source_ip)
                threat_intel_score = (
                    threat_intel_result.get("abuse_confidence_score", 0) / 100.0
                )

            # Step 7: Composite risk score (now with w4 threat-intel)
            risk_result = self.risk_scorer.compute(
                ml_confidence=ml_confidence,
                asset_criticality=asset_criticality,
                attack_severity_score=mitre_info.get("severity_score", 0.5),
                threat_intel_score=threat_intel_score,
            )

            # Check alerting threshold
            if not self.risk_scorer.should_alert(
                ml_confidence, risk_result["composite"]
            ):
                continue

            # Step 8: Build alert JSON
            alert = {
                "alert_id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "dest_port": int(dest_ports[i])
                if dest_ports and i < len(dest_ports)
                else None,
                "protocol": protocols[i] if protocols and i < len(protocols) else "TCP",
                "flow_features": flow_features_raw[i]
                if flow_features_raw and i < len(flow_features_raw)
                else {},
                "classification": {
                    "attack_class": attack_class,
                    "confidence": round(ml_confidence, 4),
                    "probabilities": {
                        class_names[j]: round(float(probabilities[i][j]), 4)
                        for j in range(len(class_names))
                    },
                    "model_name": self.model_name,
                },
                "shap_explanation": shap_explanation,
                "mitre_mapping": {
                    "technique_id": mitre_info.get("technique_id"),
                    "technique_name": mitre_info.get("technique_name"),
                    "tactic": mitre_info.get("tactic"),
                    "severity": mitre_info.get("severity"),
                    "description": mitre_info.get("description"),
                },
                "geo_context": {
                    "source": geo_source,
                    "destination": geo_dest,
                }
                if geo_source
                else None,
                "threat_intel": {
                    "source_ip": {
                        "abuse_confidence_score": threat_intel_result.get(
                            "abuse_confidence_score", 0
                        )
                        if threat_intel_result
                        else 0,
                        "total_reports": threat_intel_result.get("total_reports", 0)
                        if threat_intel_result
                        else 0,
                        "is_known_bad": threat_intel_result.get("is_known_bad", False)
                        if threat_intel_result
                        else False,
                        "last_reported_at": threat_intel_result.get("last_reported_at")
                        if threat_intel_result
                        else None,
                        "provider": threat_intel_result.get("provider", "none")
                        if threat_intel_result
                        else "none",
                    }
                }
                if threat_intel_result
                else None,
                "risk_score": risk_result,
            }

            alerts.append(alert)

        elapsed = time.time() - start_time
        logger.info(
            f"Pipeline processed {n_flows} flows → {len(alerts)} alerts "
            f"in {elapsed:.2f}s ({n_flows / max(elapsed, 0.001):.0f} flows/sec)"
        )

        return alerts
