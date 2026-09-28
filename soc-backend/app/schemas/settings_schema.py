"""
Settings schemas for tuning weights and thresholds.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ScoringWeightsUpdate(BaseModel):
    w1: float = Field(..., ge=0.0, le=1.0, description="Weight for ML confidence")
    w2: float = Field(..., ge=0.0, le=1.0, description="Weight for Asset criticality")
    w3: float = Field(..., ge=0.0, le=1.0, description="Weight for ATT&CK severity")
    w4: Optional[float] = Field(0.15, ge=0.0, le=1.0, description="Weight for Threat Intelligence reputation")


class ThresholdsUpdate(BaseModel):
    min_confidence: float = Field(0.5, ge=0.0, le=1.0)
    min_risk_score: float = Field(0.3, ge=0.0, le=1.0)


class AssetInventoryItem(BaseModel):
    ip: str
    hostname: str
    role: str
    criticality: float
    os: Optional[str] = None
    environment: Optional[str] = "Lab"


class SettingsResponse(BaseModel):
    weights: ScoringWeightsUpdate
    thresholds: ThresholdsUpdate
    assets: List[AssetInventoryItem]
