"""
Case management endpoints for security investigations.
"""


from app.database import get_db
from app.schemas.case_schema import (
    CaseCreate,
    CaseListResponse,
    CaseResponse,
    CaseUpdate,
)
from app.services.case_service import CaseService
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

router = APIRouter(prefix="/cases", tags=["Cases"])


@router.post("", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
def create_case(case_data: CaseCreate, db: Session = Depends(get_db)):
    """Create a new incident case with optional linked alerts."""
    case = CaseService.create_case(db, case_data)
    return case


@router.get("", response_model=CaseListResponse)
def list_cases(
    status: str | None = Query(
        None, description="Filter by status: open, investigating, resolved, closed"
    ),
    severity: str | None = Query(
        None, description="Filter by severity: critical, high, medium, low"
    ),
    db: Session = Depends(get_db),
):
    """List investigation cases."""
    return CaseService.list_cases(db, status=status, severity=severity)


@router.get("/{case_id}", response_model=CaseResponse)
def get_case(case_id: str, db: Session = Depends(get_db)):
    """Retrieve case details with all linked alerts."""
    case = CaseService.get_case_by_id(db, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Case not found"
        )
    return case


@router.patch("/{case_id}", response_model=CaseResponse)
def update_case(case_id: str, case_update: CaseUpdate, db: Session = Depends(get_db)):
    """Update case status, notes, or disposition."""
    updated = CaseService.update_case(db, case_id, case_update)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Case not found"
        )
    return updated
