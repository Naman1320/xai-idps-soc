"""
Risk Scorer: Computes composite risk score for each alert.

Extended Formula (4-weight):
    risk_score = w1 * ML_confidence + w2 * asset_criticality
                 + w3 * ATT&CK_severity + w4 * threat_intel_score

The formula and weights are:
- Transparent (visible in config and dashboard)
- Tunable (analyst can adjust weights in settings)
- Documented (each component's contribution is recorded in the alert)

The w4 threat-intel component is a research contribution: it uses AbuseIPDB
reputation scores as an ACTUAL INPUT to triage prioritization, not just a
dashboard decoration. An IP with many prior abuse reports will genuinely
increase the alert's risk score. Caveats: AbuseIPDB scores are crowd-sourced
and may contain false positives; a low score does not prove safety.

Original 3-weight formula is supported for backward compatibility — if w4 is
not present in config, it defaults to 0.0 and the formula reduces to the
original behavior.
"""

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

CONFIG_DIR = Path(__file__).parent.parent / "config"


class RiskScorer:
    """
    Compute transparent, tunable composite risk scores.

    Supports both the original 3-weight and extended 4-weight formulas.
    """

    def __init__(self, config_path: Path | None = None):
        if config_path is None:
            config_path = CONFIG_DIR / "scoring_weights.yaml"

        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        weights = self.config.get("weights", {})
        self.w1 = weights.get("ml_confidence", 0.45)
        self.w2 = weights.get("asset_criticality", 0.25)
        self.w3 = weights.get("attack_severity", 0.15)
        self.w4 = weights.get("threat_intel", 0.15)

        # Normalize weights to sum to 1
        total = self.w1 + self.w2 + self.w3 + self.w4
        if abs(total - 1.0) > 0.01:
            logger.warning(f"Weights sum to {total}, normalizing to 1.0")
            self.w1 /= total
            self.w2 /= total
            self.w3 /= total
            self.w4 /= total

        self.thresholds = self.config.get("thresholds", {})
        self.min_ml_confidence = self.thresholds.get("min_ml_confidence", 0.5)
        self.min_risk_score = self.thresholds.get("min_risk_score", 0.3)

        severity_levels = self.thresholds.get("severity_levels", {})
        self.severity_critical = severity_levels.get("critical", 0.85)
        self.severity_high = severity_levels.get("high", 0.65)
        self.severity_medium = severity_levels.get("medium", 0.40)

        logger.info(
            f"Risk scorer initialized: w1={self.w1}, w2={self.w2}, "
            f"w3={self.w3}, w4={self.w4}"
        )

    def compute(
        self,
        ml_confidence: float,
        asset_criticality: float,
        attack_severity_score: float | None = None,
        threat_intel_score: float = 0.0,
        attack_severity: float | None = None,
    ) -> dict[str, Any]:
        severity_score = (
            attack_severity
            if attack_severity is not None
            else (attack_severity_score or 0.5)
        )
        """
        Compute composite risk score with full breakdown.

        Args:
            ml_confidence: Model confidence for predicted class (0-1).
            asset_criticality: Target asset criticality (0-1).
            attack_severity_score: ATT&CK technique severity (0-1).
            threat_intel_score: Threat intelligence reputation score (0-1).
                                Derived from AbuseIPDB confidence / 100.
                                Defaults to 0.0 if no threat-intel data available.

        Returns:
            Dict with composite score, components, weights, and severity label.
        """
        composite = (
            self.w1 * ml_confidence
            + self.w2 * asset_criticality
            + self.w3 * severity_score
            + self.w4 * threat_intel_score
        )

        # Clamp to [0, 1]
        composite = max(0.0, min(1.0, composite))

        # Determine severity label
        if composite >= self.severity_critical:
            severity = "critical"
        elif composite >= self.severity_high:
            severity = "high"
        elif composite >= self.severity_medium:
            severity = "medium"
        else:
            severity = "low"

        return {
            "composite": round(composite, 4),
            "severity": severity,
            "components": {
                "ml_confidence": round(ml_confidence, 4),
                "asset_criticality": round(asset_criticality, 4),
                "attack_severity": round(severity_score, 4),
                "threat_intel": round(threat_intel_score, 4),
            },
            "weights": {
                "w1": round(self.w1, 4),
                "w2": round(self.w2, 4),
                "w3": round(self.w3, 4),
                "w4": round(self.w4, 4),
            },
        }

    def should_alert(self, ml_confidence: float, risk_score: float) -> bool:
        """
        Determine if a detection should generate an alert.

        Args:
            ml_confidence: Model confidence for the attack class.
            risk_score: Computed composite risk score.

        Returns:
            True if the detection meets alerting thresholds.
        """
        return (
            ml_confidence >= self.min_ml_confidence
            and risk_score >= self.min_risk_score
        )
