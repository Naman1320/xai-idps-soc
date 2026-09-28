"""
Settings endpoints for tuning composite risk scoring weights,
alert thresholds, and reading asset inventories.
"""

from typing import List
from fastapi import APIRouter, HTTPException, status

from app.config import settings
from app.schemas.settings_schema import (
    ScoringWeightsUpdate,
    ThresholdsUpdate,
    AssetInventoryItem,
    SettingsResponse,
)

router = APIRouter(prefix="/settings", tags=["Settings"])

# In-memory/configured runtime state (can be saved to YAML or DB)
runtime_weights = {
    "w1": settings.WEIGHT_ML_CONFIDENCE,
    "w2": settings.WEIGHT_ASSET_CRITICALITY,
    "w3": settings.WEIGHT_ATTACK_SEVERITY,
    "w4": settings.WEIGHT_THREAT_INTEL,
}

runtime_thresholds = {
    "min_confidence": 0.50,
    "min_risk_score": settings.MIN_RISK_SCORE_ALERT
}

demo_assets = [
    AssetInventoryItem(ip="10.0.0.5", hostname="dc01.corp.local", role="Domain Controller", criticality=0.95, os="Windows Server 2022", environment="DMZ/Core"),
    AssetInventoryItem(ip="10.0.0.10", hostname="web-prod-01", role="Web Server (NGINX)", criticality=0.90, os="Ubuntu 22.04 LTS", environment="DMZ"),
    AssetInventoryItem(ip="10.0.0.15", hostname="bastion-ssh", role="Management Jump Host", criticality=0.85, os="Debian 12", environment="Management"),
    AssetInventoryItem(ip="10.0.0.20", hostname="ftp-repo-01", role="Internal File Server", criticality=0.70, os="Ubuntu 20.04 LTS", environment="Internal"),
    AssetInventoryItem(ip="10.0.0.25", hostname="sql-cluster-01", role="Database Server", criticality=0.90, os="RHEL 9", environment="Backend"),
    AssetInventoryItem(ip="10.0.0.32", hostname="workstation-admin", role="Admin Workstation", criticality=0.75, os="Windows 11 Enterprise", environment="Corporate LAN"),
    AssetInventoryItem(ip="10.0.0.45", hostname="dev-node-03", role="CI/CD Build Runner", criticality=0.60, os="Ubuntu 22.04 LTS", environment="Engineering"),
    AssetInventoryItem(ip="10.0.0.50", hostname="dns-cache-01", role="DNS Resolver", criticality=0.80, os="Alpine Linux", environment="Core Network"),
]


@router.get("", response_model=SettingsResponse)
def get_settings():
    """Get active composite scoring weights, thresholds, and asset context table."""
    return SettingsResponse(
        weights=ScoringWeightsUpdate(**runtime_weights),
        thresholds=ThresholdsUpdate(**runtime_thresholds),
        assets=demo_assets
    )


@router.post("/weights", response_model=ScoringWeightsUpdate)
def update_weights(weights_data: ScoringWeightsUpdate):
    """
    Update composite risk scoring weights (w1: ML confidence, w2: Asset criticality, w3: ATT&CK severity, w4: Threat intelligence).
    Validates that weights sum approximately to 1.0.
    """
    w4 = weights_data.w4 if weights_data.w4 is not None else 0.0
    total = weights_data.w1 + weights_data.w2 + weights_data.w3 + w4
    if not (0.95 <= total <= 1.05):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Weights must sum to 1.0 (current sum: {total:.2f})"
        )

    runtime_weights["w1"] = weights_data.w1
    runtime_weights["w2"] = weights_data.w2
    runtime_weights["w3"] = weights_data.w3
    runtime_weights["w4"] = w4
    return weights_data


@router.get("/assets", response_model=List[AssetInventoryItem])
def get_assets():
    """Retrieve network asset inventory with IP and criticality ratings."""
    return demo_assets
