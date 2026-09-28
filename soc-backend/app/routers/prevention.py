"""
Automated IPS (Intrusion Prevention System) and Firewall Rule Management router.
"""


from app.database import get_db
from app.services.prevention_service import PreventionService
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

router = APIRouter(prefix="/prevention", tags=["Intrusion Prevention (IPS)"])


class BlockRequest(BaseModel):
    ip: str = Field(..., description="Target IP to block at perimeter firewall")
    reason: str = Field(..., description="Justification or correlated MITRE technique")
    attack_class: str | None = "Unknown"
    risk_score: float | None = 0.85
    duration_minutes: int | None = 60
    dest_port: int | None = None


class UnblockRequest(BaseModel):
    ip: str


class DryRunToggle(BaseModel):
    enabled: bool


@router.get("/status")
def get_ips_status():
    """Get active IPS operational status, dry-run state, and block counts."""
    return PreventionService.get_status()


@router.post("/dry-run")
def toggle_dry_run(toggle: DryRunToggle):
    """Toggle dry-run safety harness (prevents accidental lockout during demonstrations)."""
    val = PreventionService.set_dry_run(toggle.enabled)
    return {"status": "success", "dry_run": val}


@router.get("/blocks")
def list_blocked_ips():
    """List all currently active IPS firewall drops and expiration timers."""
    return PreventionService.list_blocks()


@router.post("/block", status_code=status.HTTP_201_CREATED)
def block_ip(req: BlockRequest, db: Session = Depends(get_db)):
    """Deploy an active perimeter firewall drop rule."""
    res = PreventionService.block_ip(
        ip=req.ip,
        reason=req.reason,
        attack_class=req.attack_class or "Unknown",
        risk_score=req.risk_score or 0.85,
        duration_minutes=req.duration_minutes or 60,
        triggered_by="analyst",
        db=db,
    )
    # Generate multi-platform firewall commands
    rules = PreventionService.generate_firewall_rules(
        req.ip, req.attack_class or "Threat", req.dest_port
    )
    return {"status": "success", "block": res, "syntax_preview": rules}


@router.post("/unblock")
def unblock_ip(req: UnblockRequest, db: Session = Depends(get_db)):
    """Release an active firewall block."""
    ok = PreventionService.unblock_ip(req.ip, db=db)
    if not ok:
        raise HTTPException(status_code=404, detail="IP is not currently blocked")
    return {"status": "success", "message": f"IP {req.ip} unblocked successfully"}
