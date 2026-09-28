"""
Case management service for security incident investigation and disposition.
"""

import uuid
from datetime import datetime
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.case import Case
from app.models.alert import Alert
from app.schemas.case_schema import CaseCreate, CaseUpdate, CaseResponse, CaseListResponse
from app.schemas.alert_schema import AlertResponse


class CaseService:

    @staticmethod
    def create_case(db: Session, data: CaseCreate) -> Case:
        """Create a new incident investigation case."""
        case_id = str(uuid.uuid4())
        case = Case(
            id=case_id,
            title=data.title,
            status="open",
            severity=data.severity,
            assigned_to=data.assigned_to or "analyst",
            notes=data.notes,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

        if data.alert_ids:
            alerts = db.query(Alert).filter(Alert.id.in_(data.alert_ids)).all()
            case.alerts = alerts
            # Auto update alert status to investigating
            for a in alerts:
                if a.status == "new":
                    a.status = "investigating"

        db.add(case)
        db.commit()
        db.refresh(case)
        return case

    @staticmethod
    def list_cases(
        db: Session,
        status: Optional[str] = None,
        severity: Optional[str] = None
    ) -> CaseListResponse:
        """List cases with optional filters."""
        query = db.query(Case)
        if status:
            query = query.filter(Case.status == status)
        if severity:
            query = query.filter(Case.severity == severity)

        cases = query.order_by(desc(Case.updated_at)).all()
        total = len(cases)

        case_responses = []
        for c in cases:
            resp = CaseResponse.model_validate(c)
            case_responses.append(resp)

        return CaseListResponse(cases=case_responses, total=total)

    @staticmethod
    def get_case_by_id(db: Session, case_id: str) -> Optional[Case]:
        """Fetch a specific case with its linked alerts."""
        return db.query(Case).filter(Case.id == case_id).first()

    @staticmethod
    def update_case(db: Session, case_id: str, data: CaseUpdate) -> Optional[Case]:
        """Update case status, notes, disposition, or alert assignments."""
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            return None

        if data.title is not None:
            case.title = data.title
        if data.status is not None:
            case.status = data.status
            # If case resolved or closed, optionally update alert status
            if data.status in ["resolved", "closed"]:
                for alert in case.alerts:
                    alert.status = data.status
        if data.severity is not None:
            case.severity = data.severity
        if data.assigned_to is not None:
            case.assigned_to = data.assigned_to
        if data.notes is not None:
            case.notes = data.notes
        if data.disposition is not None:
            case.disposition = data.disposition

        if data.alert_ids is not None:
            alerts = db.query(Alert).filter(Alert.id.in_(data.alert_ids)).all()
            case.alerts = alerts

        case.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(case)
        return case
