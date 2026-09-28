"""
Analytics schemas for metrics, summary stats, and ATT&CK coverage.
"""

from typing import Any

from pydantic import BaseModel


class StatusBreakdown(BaseModel):
    new: int = 0
    investigating: int = 0
    resolved: int = 0
    dismissed: int = 0
    closed: int = 0


class AttackClassCount(BaseModel):
    attack_class: str
    count: int
    avg_risk: float
    percentage: float


class MitreTechniqueStat(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    severity: str
    count: int


class TimelineDataPoint(BaseModel):
    timestamp: str
    count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int


class AnalyticsSummary(BaseModel):
    total_alerts: int
    open_cases: int
    critical_alerts: int
    average_risk_score: float
    false_positive_rate: float
    status_breakdown: StatusBreakdown
    attack_classes: list[AttackClassCount]
    top_mitre_techniques: list[MitreTechniqueStat]
    domain_breakdown: dict[str, Any] | None = None
    dataset_breakdown: dict[str, int] | None = None
    dataset_health: list[dict[str, Any]] | None = None
    kpi: dict[str, Any] | None = None


class ModelEvaluationMetric(BaseModel):
    class_name: str
    precision: float
    recall: float
    f1_score: float
    support: int


class AnalyticsMetricsResponse(BaseModel):
    macro_f1: float
    overall_fpr: float
    ingestion_latency_ms: float
    precision_at_10: float
    precision_at_50: float
    evaluation_metrics: list[ModelEvaluationMetric]
