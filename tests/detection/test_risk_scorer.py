"""
Tests for RiskScorer transparent composite formula.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../detection")))

from enrichment.risk_scorer import RiskScorer


def test_risk_score_computation():
    """Verify formula: risk = w1*conf + w2*asset + w3*severity."""
    scorer = RiskScorer()
    # Test values: confidence=0.9, asset=0.8, attack_severity=0.7
    result = scorer.compute(ml_confidence=0.9, asset_criticality=0.8, attack_severity_score=0.7)
    
    assert "composite" in result
    assert "components" in result
    assert "weights" in result
    assert "severity" in result

    # Expected: 0.5*0.9 + 0.3*0.8 + 0.2*0.7 = 0.45 + 0.24 + 0.14 = 0.83
    assert abs(result["composite"] - 0.83) < 0.01
    assert result["severity"] == "high"


def test_risk_score_clamping():
    """Verify scores are clamped between 0 and 1."""
    scorer = RiskScorer()
    res_high = scorer.compute(ml_confidence=1.5, asset_criticality=1.2, attack_severity_score=1.0)
    assert res_high["composite"] <= 1.0

    res_low = scorer.compute(ml_confidence=-0.5, asset_criticality=-0.1, attack_severity_score=0.0)
    assert res_low["composite"] >= 0.0


def test_should_alert():
    """Verify threshold evaluation."""
    scorer = RiskScorer()
    assert scorer.should_alert(ml_confidence=0.95, risk_score=0.85) is True
    assert scorer.should_alert(ml_confidence=0.20, risk_score=0.85) is False
    assert scorer.should_alert(ml_confidence=0.90, risk_score=0.15) is False
