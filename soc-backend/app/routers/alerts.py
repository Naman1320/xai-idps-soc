"""
Alert ingestion, listing, detail, and SHAP explanation endpoints.
"""

from typing import Optional, List, Union
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.alert_schema import (
    AlertIngestSchema,
    AlertResponse,
    AlertListResponse,
    AlertStatusUpdate,
    AlertExplanationResponse,
)
from app.services.alert_service import AlertService
from app.middleware.auth_middleware import verify_ingestion_api_key

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.post("", status_code=status.HTTP_201_CREATED)
def ingest_alert(
    payload: Union[AlertIngestSchema, List[AlertIngestSchema]],
    db: Session = Depends(get_db),
    _authorized: bool = Depends(verify_ingestion_api_key)
):
    """
    Ingest one or multiple alerts from the ML detection pipeline.
    Carries classification, SHAP explanations, ATT&CK mapping, and risk score.
    """
    if isinstance(payload, list):
        created_ids = []
        for item in payload:
            alert = AlertService.ingest_alert(db, item)
            created_ids.append(alert.id)
        return {
            "status": "success",
            "message": f"Successfully ingested {len(created_ids)} alerts",
            "alert_ids": created_ids
        }
    else:
        alert = AlertService.ingest_alert(db, payload)
        return {
            "status": "success",
            "alert_id": alert.id,
            "ingested_at": alert.ingested_at.isoformat()
        }


@router.get("", response_model=AlertListResponse)
def list_alerts(
    status: Optional[str] = Query(None, description="Filter by status: new, investigating, resolved, closed"),
    attack_class: Optional[str] = Query(None, description="Filter by attack class: DDoS, PortScan, etc."),
    severity: Optional[str] = Query(None, description="Filter by MITRE severity: High, Medium, Low"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    dest_ip: Optional[str] = Query(None, description="Filter by destination IP"),
    min_risk: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum risk score"),
    search: Optional[str] = Query(None, description="Global text search across IPs and attack names"),
    sort_by: str = Query("risk_score", description="Field to sort by: risk_score, detected_at, ml_confidence"),
    order: str = Query("desc", description="Sort order: asc, desc"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(25, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db)
):
    """List alerts with filtering, search, sorting and pagination."""
    return AlertService.list_alerts(
        db=db,
        status=status,
        attack_class=attack_class,
        severity=severity,
        source_ip=source_ip,
        dest_ip=dest_ip,
        min_risk=min_risk,
        search=search,
        sort_by=sort_by,
        order=order,
        page=page,
        limit=limit
    )


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: str, db: Session = Depends(get_db)):
    """Fetch single alert with full details and SHAP feature contributions."""
    alert = AlertService.get_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert


@router.get("/{alert_id}/explanation", response_model=AlertExplanationResponse)
def get_alert_explanation(alert_id: str, db: Session = Depends(get_db)):
    """
    Retrieve SHAP waterfall explanation data, top contributing flow features,
    and plain language analyst narrative.
    """
    explanation = AlertService.get_explanation(db, alert_id)
    if not explanation:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert or explanation not found")
    return explanation


@router.patch("/{alert_id}/status", response_model=AlertResponse)
def update_alert_status(
    alert_id: str,
    status_update: AlertStatusUpdate,
    db: Session = Depends(get_db)
):
    """Update alert triage status (new, investigating, resolved, closed)."""
    alert = AlertService.update_status(db, alert_id, status_update.status)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert


@router.delete("/{alert_id}")
def delete_alert(alert_id: str, db: Session = Depends(get_db)):
    """Delete an alert."""
    success = AlertService.delete_alert(db, alert_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return {"status": "success", "message": "Alert deleted"}
