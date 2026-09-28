"""
Analyst feedback endpoints for logging alert ground-truth and disposition.
"""

import uuid
from datetime import datetime

from app.database import get_db
from app.middleware.auth_middleware import get_optional_current_user
from app.models.alert import Alert
from app.models.feedback import Feedback
from app.schemas.feedback_schema import FeedbackCreate, FeedbackResponse
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc
from sqlalchemy.orm import Session

router = APIRouter(tags=["Feedback"])


@router.post(
    "/alerts/{alert_id}/feedback",
    response_model=FeedbackResponse,
    status_code=status.HTTP_201_CREATED,
)
def submit_feedback(
    alert_id: str,
    feedback_data: FeedbackCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_optional_current_user),
):
    """
    Submit analyst ground-truth feedback (true_positive / false_positive / unknown).
    Recorded for FPR evaluation and continuous threshold calibration.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found"
        )

    username = current_user.username if current_user else "analyst"
    fb = Feedback(
        id=str(uuid.uuid4()),
        alert_id=alert_id,
        user_id=username,
        disposition=feedback_data.disposition,
        notes=feedback_data.notes,
        created_at=datetime.utcnow(),
    )
    db.add(fb)

    # If marked false_positive, we can auto-resolve the alert
    if feedback_data.disposition == "false_positive":
        alert.status = "dismissed"
    elif feedback_data.disposition == "true_positive":
        if alert.status == "new":
            alert.status = "investigating"

    db.commit()
    db.refresh(fb)
    return fb


@router.get("/feedback", response_model=list[FeedbackResponse])
def list_feedback(limit: int = 50, db: Session = Depends(get_db)):
    """List recent analyst feedback logs."""
    return db.query(Feedback).order_by(desc(Feedback.created_at)).limit(limit).all()
