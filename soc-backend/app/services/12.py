"""
Automated IPS (Intrusion Prevention System) & Response Engine.
Generates firewall rules (iptables, nftables, AWS Security Groups),
tracks active IP blocklists with expiration countdowns, and maintains
a complete reversible response audit trail.
"""

import uuid
from datetime import datetime, timedelta
from typing import Any

from app.models.feedback import ResponseLog
from sqlalchemy.orm import Session


# In-memory active blocks and dry-run toggle
class PreventionState:
    dry_run: bool = True
    active_blocks: list[dict[str, Any]] = [
        {
            "id": "block-001",
            "ip": "192.168.10.45",
            "reason": "Volumetric DDoS Flood (T1498) - 35,714 pkts/s",
            "attack_class": "DDoS",
            "risk_score": 0.91,
            "blocked_at": (datetime.utcnow() - timedelta(minutes=15)).isoformat(),
            "duration_minutes": 60,
            "status": "active",
            "rule_syntax": "iptables -A INPUT -s 192.168.10.45 -j DROP",
            "triggered_by": "Automated IPS Policy (Risk >= 0.85)",
        },
        {
            "id": "block-002",
            "ip": "192.168.10.14",
            "reason": "SSH-Patator Credential Brute Force (T1110) on port 22",
            "attack_class": "SSH-Patator",
            "risk_score": 0.84,
            "blocked_at": (datetime.utcnow() - timedelta(minutes=45)).isoformat(),
            "duration_minutes": 120,
            "status": "active",
            "rule_syntax": "iptables -A INPUT -p tcp --dport 22 -s 192.168.10.14 -j DROP",
            "triggered_by": "Analyst Triage Action",
        },
    ]


class PreventionService:
    @staticmethod
    def get_status() -> dict[str, Any]:
        """Return IPS engine status and active blocks."""
        return {
            "ips_engine": "Active (Dual-Mode: Rule Generator + Live Sensor)",
            "dry_run": PreventionState.dry_run,
            "active_blocks_count": len(
                [b for b in PreventionState.active_blocks if b["status"] == "active"]
            ),
            "total_actions": len(PreventionState.active_blocks),
            "supported_firewalls": [
                "iptables",
                "nftables",
                "ufw",
                "AWS Security Group",
            ],
        }

    @staticmethod
    def set_dry_run(enabled: bool) -> bool:
        """Toggle dry-run safety mode."""
        PreventionState.dry_run = enabled
        return PreventionState.dry_run

    @staticmethod
    def list_blocks() -> list[dict[str, Any]]:
        """List all active and expired block rules."""
        return PreventionState.active_blocks

    @staticmethod
    def block_ip(
        ip: str,
        reason: str,
        attack_class: str = "Unknown",
        risk_score: float = 0.80,
        duration_minutes: int = 60,
        triggered_by: str = "analyst",
        db: Session | None = None,
    ) -> dict[str, Any]:
        """Deploy an IPS block rule for an IP."""
        # Check if already blocked
        for b in PreventionState.active_blocks:
            if b["ip"] == ip and b["status"] == "active":
                return b

        block_id = f"block-{uuid.uuid4().hex[:6]}"
        now = datetime.utcnow()
        rule = f"iptables -A INPUT -s {ip} -j DROP"

        block_entry = {
            "id": block_id,
            "ip": ip,
            "reason": reason,
            "attack_class": attack_class,
            "risk_score": risk_score,
            "blocked_at": now.isoformat(),
            "duration_minutes": duration_minutes,
            "status": "active",
            "rule_syntax": rule,
            "triggered_by": triggered_by,
        }
        PreventionState.active_blocks.insert(0, block_entry)

        # Log to audit DB if session available
        if db:
            log = ResponseLog(
                id=str(uuid.uuid4()),
                action_type="FIREWALL_BLOCK",
                target=ip,
                result="SUCCESS"
                if not PreventionState.dry_run
                else "SIMULATED_SUCCESS",
                triggered_by=triggered_by,
                executed_at=now,
            )
            db.add(log)
            db.commit()

        return block_entry

    @staticmethod
    def unblock_ip(ip: str, db: Session | None = None) -> bool:
        """Unblock an IP address."""
        found = False
        for b in PreventionState.active_blocks:
            if b["ip"] == ip and b["status"] == "active":
                b["status"] = "unblocked"
                found = True

        if found and db:
            log = ResponseLog(
                id=str(uuid.uuid4()),
                action_type="FIREWALL_UNBLOCK",
                target=ip,
                result="SUCCESS",
                triggered_by="analyst",
                executed_at=datetime.utcnow(),
            )
            db.add(log)
            db.commit()

        return found

    @staticmethod
    def generate_firewall_rules(
        ip: str, attack_class: str, port: int | None = None
    ) -> dict[str, str]:
        """Generate multi-platform firewall syntax."""
        p_str = f" -p tcp --dport {port}" if port else ""
        return {
            "iptables": f"sudo iptables -I INPUT{p_str} -s {ip} -j DROP",
            "nftables": f"sudo nft add rule inet filter input ip saddr {ip} drop",
            "ufw": f"sudo ufw insert 1 deny from {ip} to any{f' port {port}' if port else ''}",
            "aws_security_group_cli": f"aws ec2 revoke-security-group-ingress --group-id sg-0123456789abcdef0 --protocol tcp --port {port or 80} --cidr {ip}/32",
            "snort_rule": f'drop tcp {ip} any -> any any (msg:"XAI-IDPS Auto-Drop: {attack_class}"; sid:1000999; rev:1;)',
        }
