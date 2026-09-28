"""
Analytics endpoints for SOC operational intelligence and evaluation metrics.
"""


from app.database import get_db
from app.schemas.analytics_schema import (
    AnalyticsMetricsResponse,
    AnalyticsSummary,
    TimelineDataPoint,
)
from app.services.analytics_service import AnalyticsService
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

router = APIRouter(prefix="/analytics", tags=["Analytics"])


@router.get("/summary", response_model=AnalyticsSummary)
def get_analytics_summary(db: Session = Depends(get_db)):
    """Retrieve high-level SOC statistics, attack distributions, and MITRE frequencies."""
    return AnalyticsService.get_summary(db)


@router.get("/timeline", response_model=list[TimelineDataPoint])
def get_timeline(hours: int = Query(48, ge=12, le=168), db: Session = Depends(get_db)):
    """Retrieve time-series alert frequency grouped into severity intervals."""
    return AnalyticsService.get_timeline(db, hours=hours)


@router.get("/metrics", response_model=AnalyticsMetricsResponse)
def get_evaluation_metrics():
    """Retrieve ML evaluation metrics, FPR comparisons, and Precision@K results."""
    return AnalyticsService.get_metrics()
