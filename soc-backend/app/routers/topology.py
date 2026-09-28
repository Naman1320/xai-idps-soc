"""
Digital Twin & Network Topology API router.
Provides live nodes, zones, and threat traffic vectors for interactive canvas rendering.
"""

from app.database import get_db
from app.models.alert import Alert
from fastapi import APIRouter, Depends
from sqlalchemy import desc
from sqlalchemy.orm import Session

router = APIRouter(prefix="/topology", tags=["Digital Twin & Topology"])


@router.get("/graph")
def get_topology_graph(db: Session = Depends(get_db)):
    """
    Return network zones, hosts, sensor placements, and active threat vectors.
    """
    recent_alerts = db.query(Alert).order_by(desc(Alert.detected_at)).limit(10).all()

    nodes = [
        {
            "id": "ext-attacker",
            "label": "External Threat Subnet",
            "type": "threat",
            "zone": "WAN",
            "ip": "192.168.10.x",
            "criticality": 0.0,
        },
        {
            "id": "edge-firewall",
            "label": "Perimeter Next-Gen Firewall",
            "type": "firewall",
            "zone": "Perimeter",
            "ip": "10.0.0.1",
            "criticality": 0.8,
        },
        {
            "id": "ids-sensor",
            "label": "XAI-IDPS Sensor (CICFlowMeter)",
            "type": "sensor",
            "zone": "Perimeter",
            "ip": "10.0.0.2",
            "criticality": 0.75,
        },
        {
            "id": "web-dmz",
            "label": "DMZ Web Server (Nginx)",
            "type": "server",
            "zone": "DMZ",
            "ip": "10.0.0.10",
            "criticality": 0.90,
        },
        {
            "id": "bastion-ssh",
            "label": "Management Bastion Host",
            "type": "server",
            "zone": "Management",
            "ip": "10.0.0.15",
            "criticality": 0.85,
        },
        {
            "id": "sql-db",
            "label": "Core SQL Database Cluster",
            "type": "database",
            "zone": "Internal LAN",
            "ip": "10.0.0.25",
            "criticality": 0.95,
        },
        {
            "id": "lan-ws",
            "label": "Engineering Workstations",
            "type": "workstation",
            "zone": "Internal LAN",
            "ip": "10.0.0.32",
            "criticality": 0.60,
        },
    ]

    links = [
        {
            "source": "ext-attacker",
            "target": "edge-firewall",
            "type": "ingress",
            "status": "monitored",
        },
        {
            "source": "edge-firewall",
            "target": "ids-sensor",
            "type": "span_port",
            "status": "inspecting",
        },
        {
            "source": "edge-firewall",
            "target": "web-dmz",
            "type": "forwarded",
            "status": "active",
        },
        {
            "source": "edge-firewall",
            "target": "bastion-ssh",
            "type": "forwarded",
            "status": "active",
        },
        {
            "source": "web-dmz",
            "target": "sql-db",
            "type": "internal_query",
            "status": "active",
        },
        {
            "source": "lan-ws",
            "target": "bastion-ssh",
            "type": "management",
            "status": "active",
        },
    ]

    active_threats = []
    for a in recent_alerts:
        active_threats.append(
            {
                "alert_id": a.id,
                "source_ip": a.source_ip,
                "dest_ip": a.dest_ip,
                "attack_class": a.attack_class,
                "risk_score": a.risk_score,
                "mitre_id": a.mitre_technique_id or "T1498",
            }
        )

    return {"nodes": nodes, "links": links, "active_threats": active_threats}
