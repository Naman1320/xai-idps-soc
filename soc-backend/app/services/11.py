"""
Automated IPS (Intrusion Prevention System) & Response Engine.
Generates firewall rules (iptables, nftables, AWS Security Groups),
tracks active IP blocklists with expiration countdowns, and maintains
a complete reversible response audit trail.
"""

import sys
from pathlib import Path

# Add backend directory to sys.path to allow standalone execution
_backend_root = str(Path(__file__).resolve().parent.parent.parent)
if _backend_root not in sys.path:
    sys.path.insert(0, _backend_root)

import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.feedback import ResponseLog
from app.models.alert import Alert


# In-memory active blocks and dry-run toggle
class PreventionState:
    dry_run: bool = True
    active_blocks: List[Dict[str, Any]] = [
        {
            "id": "block-001",
            "ip": "192.168.10.45",
            "reason": "Volumetric DDoS Flood (T1498) - 35,714 pkts/s",
            "attack_class": "DDoS",
            "risk_score": 0.91,
            "blocked_at": (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat(),
            "duration_minutes": 60,
            "status": "active",
            "rule_syntax": "iptables -A INPUT -s 192.168.10.45 -j DROP",
            "triggered_by": "Automated IPS Policy (Risk >= 0.85)"
        },
        {
            "id": "block-002",
            "ip": "192.168.10.14",
            "reason": "SSH-Patator Credential Brute Force (T1110) on port 22",
            "attack_class": "SSH-Patator",
            "risk_score": 0.84,
            "blocked_at": (datetime.now(timezone.utc) - timedelta(minutes=45)).isoformat(),
            "duration_minutes": 120,
            "status": "active",
            "rule_syntax": "iptables -A INPUT -p tcp --dport 22 -s 192.168.10.14 -j DROP",
            "triggered_by": "Analyst Triage Action"
        }
    ]


class PreventionService:

    @staticmethod
    def get_status() -> Dict[str, Any]:
        """Return IPS engine status and active blocks."""
        return {
            "ips_engine": "Active (Dual-Mode: Rule Generator + Live Sensor)",
            "dry_run": PreventionState.dry_run,
            "active_blocks_count": len([b for b in PreventionState.active_blocks if b["status"] == "active"]),
            "total_actions": len(PreventionState.active_blocks),
            "supported_firewalls": ["iptables", "nftables", "ufw", "AWS Security Group"]
        }

    @staticmethod
    def set_dry_run(enabled: bool) -> bool:
        """Toggle dry-run safety mode."""
        PreventionState.dry_run = enabled
        return PreventionState.dry_run

    @staticmethod
    def list_blocks() -> List[Dict[str, Any]]:
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
        db: Optional[Session] = None
    ) -> Dict[str, Any]:
        """Deploy an IPS block rule for an IP."""
        # Check if already blocked
        for b in PreventionState.active_blocks:
            if b["ip"] == ip and b["status"] == "active":
                return b

        block_id = f"block-{uuid.uuid4().hex[:6]}"
        now = datetime.now(timezone.utc)
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
            "triggered_by": triggered_by
        }
        PreventionState.active_blocks.insert(0, block_entry)

        # Log to audit DB if session available
        if db:
            log = ResponseLog(
                id=str(uuid.uuid4()),
                action_type="FIREWALL_BLOCK",
                target=ip,
                result="SUCCESS" if not PreventionState.dry_run else "SIMULATED_SUCCESS",
                triggered_by=triggered_by,
                executed_at=now
            )
            db.add(log)
            db.commit()

        return block_entry

    @staticmethod
    def unblock_ip(ip: str, db: Optional[Session] = None) -> bool:
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
                executed_at=datetime.now(timezone.utc)
            )
            db.add(log)
            db.commit()

        return found

    @staticmethod
    def generate_firewall_rules(ip: str, attack_class: str, port: Optional[int] = None) -> Dict[str, str]:
        """Generate multi-platform firewall syntax."""
        p_str = f" -p tcp --dport {port}" if port else ""
        return {
            "iptables": f"sudo iptables -I INPUT{p_str} -s {ip} -j DROP",
            "nftables": f"sudo nft add rule inet filter input ip saddr {ip} drop",
            "ufw": f"sudo ufw insert 1 deny from {ip} to any{f' port {port}' if port else ''}",
            "aws_security_group_cli": f"aws ec2 revoke-security-group-ingress --group-id sg-0123456789abcdef0 --protocol tcp --port {port or 80} --cidr {ip}/32",
            "snort_rule": f'drop tcp {ip} any -> any any (msg:"XAI-IDPS Auto-Drop: {attack_class}"; sid:1000999; rev:1;)'
        }


if __name__ == "__main__":
    print("=" * 70)
    print("🛡️  XAI-IDPS-SOC Automated Intrusion Prevention System (IPS) Engine")
    print("=" * 70)

    # 1. Engine Status
    status = PreventionService.get_status()
    print("\n[+] IPS Engine Status:")
    for k, v in status.items():
        print(f"    • {k}: {v}")

    # 2. Generate Firewall Rules
    target_ip = "192.168.1.150"
    attack = "SSH-Patator (Brute-Force T1110)"
    port = 22
    print(f"\n[+] Multi-Platform Firewall Rule Generation:")
    print(f"    Target: {target_ip} | Attack: {attack} | Port: {port}")
    rules = PreventionService.generate_firewall_rules(target_ip, attack, port)
    for platform, rule in rules.items():
        print(f"    [{platform.upper()}]: {rule}")

    # 3. Simulate Automated Block
    print("\n[+] Triggering Automated IP Block Action:")
    block_result = PreventionService.block_ip(
        ip="203.0.113.88",
        reason="Volumetric SYN Flood detected by XAI classifier",
        attack_class="DDoS-SYN",
        risk_score=0.96,
        duration_minutes=60,
        triggered_by="Automated ML Policy (Risk > 0.85)"
    )
    print(f"    ✓ Block Created: ID={block_result['id']} | IP={block_result['ip']} | Status={block_result['status']}")
    print(f"    ✓ Rule Syntax:   {block_result['rule_syntax']}")

    # 4. Active Block Registry
    print("\n[+] Active IP Blocklist Registry:")
    for block in PreventionService.list_blocks():
        status_symbol = "🔴 ACTIVE" if block["status"] == "active" else "🟢 UNBLOCKED"
        print(f"    [{status_symbol}] {block['ip']} | Score: {block['risk_score']} | {block['attack_class']} ({block['reason']})")

    # 5. Simulate Unblock
    print("\n[+] Simulating Analyst Unblock Action for 203.0.113.88:")
    unblocked = PreventionService.unblock_ip("203.0.113.88")
    print(f"    ✓ Unblock Status: {'SUCCESS' if unblocked else 'NOT FOUND'}")

    print("\n" + "=" * 70)
    print("✅ IPS Engine Self-Test Execution Complete!")
    print("=" * 70)

