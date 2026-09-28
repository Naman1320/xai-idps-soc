"""
AI Security Copilot API router.
"""

from typing import Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.copilot_service import CopilotService

router = APIRouter(prefix="/copilot", tags=["AI Copilot"])


class CopilotQueryRequest(BaseModel):
    query: str = Field(..., description="Analyst question or instruction")
    alert_id: Optional[str] = Field(None, description="Optional alert ID for contextual reasoning")


@router.post("/query")
def ask_copilot(req: CopilotQueryRequest, db: Session = Depends(get_db)):
    """
    Query the AI Copilot for natural language alert analysis,
    SHAP explainability interpretation, and containment recommendations.
    """
    return CopilotService.answer_query(query=req.query, alert_id=req.alert_id, db=db)
