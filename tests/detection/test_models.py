"""
Tests for Detection Models and Evaluator.
"""

import sys
import os
import numpy as np
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../detection")))

from models.baseline import BaselineModel
from models.evaluator import ModelEvaluator


def test_baseline_model_train_and_predict():
    """Verify BaselineModel can fit and predict on synthetic feature vectors."""
    np.random.seed(42)
    X = np.random.randn(50, 10)
    y = np.random.choice([0, 1], size=50)

    model = BaselineModel()
    model.train(X, y)

    preds = model.predict(X[:5])
    assert len(preds) == 5
    proba = model.predict_proba(X[:5])
    assert proba.shape == (5, 2)


def test_model_evaluator_metrics():
    """Verify ModelEvaluator computes precision, recall, f1, and FPR."""
    y_true = np.array([0, 1, 0, 1, 0, 1, 0, 0])
    y_pred = np.array([0, 1, 0, 1, 0, 0, 0, 0])

    evaluator = ModelEvaluator(class_names=["Benign", "Attack"])
    metrics = evaluator.evaluate(y_true, y_pred, model_name="test_model")

    assert "macro_f1" in metrics
    assert "weighted_f1" in metrics
    assert "confusion_matrix" in metrics
    assert "per_class" in metrics
    assert metrics["macro_f1"] > 0.5
