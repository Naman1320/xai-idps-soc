"""
Seed service to populate realistic initial detection alerts,
SHAP feature explanations, MITRE ATT&CK mappings, geolocation context,
threat intelligence data, and demo cases.
Ensures instant demonstration readiness upon first startup.
"""

import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.alert import Alert, AlertShapFeature
from app.models.case import Case
from app.models.feedback import Feedback
from app.middleware.auth_middleware import hash_password
from app.config import settings


def seed_database(db: Session) -> None:
    """Initialize default users and demo security telemetry if empty."""
    # 1. Seed Users (Admin, Manager, Employee, Analyst)
    initial_profiles = [
        {"username": settings.DEFAULT_ADMIN_USERNAME, "password": settings.DEFAULT_ADMIN_PASSWORD, "role": "admin"},
        {"username": "manager", "password": "manager123", "role": "manager"},
        {"username": "employee", "password": "employee123", "role": "employee"},
        {"username": "analyst", "password": "analyst123", "role": "analyst"},
    ]
    for p in initial_profiles:
        if not db.query(User).filter(User.username == p["username"]).first():
            db.add(User(
                id=str(uuid.uuid4()),
                username=p["username"],
                password_hash=hash_password(p["password"]),
                role=p["role"],
                created_at=datetime.utcnow()
            ))
    db.commit()

    # 2. Seed Alerts if none exist
    if db.query(Alert).count() == 0:
        now = datetime.utcnow()
        
        sample_alerts_data = [
            {
                "attack_class": "DDoS",
                "ml_confidence": 0.965,
                "source_ip": "192.168.10.45",
                "dest_ip": "10.0.0.10",
                "dest_port": 80,
                "protocol": "TCP",
                "time_offset_mins": 12,
                "mitre_id": "T1498",
                "mitre_name": "Network Denial of Service",
                "mitre_tactic": "Impact",
                "mitre_severity": "High",
                "mitre_desc": "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources.",
                "asset_crit": 0.95,
                "risk_score": 0.91,
                "status": "investigating",
                "features": {
                    "fwd_pkt_len_mean": 1420.5,
                    "flow_duration": 0.0028,
                    "flow_pkts_per_sec": 35714.2,
                    "bwd_pkt_len_mean": 42.0,
                    "syn_flag_count": 1,
                    "flow_bytes_per_sec": 50714285.0
                },
                "shap": [
                    {"feature": "Flow Packets/s", "shap": 0.385, "val": 35714.2, "rank": 1},
                    {"feature": "Fwd Packet Length Mean", "shap": 0.285, "val": 1420.5, "rank": 2},
                    {"feature": "Flow Duration", "shap": 0.175, "val": 0.0028, "rank": 3},
                    {"feature": "SYN Flag Count", "shap": 0.080, "val": 1.0, "rank": 4},
                    {"feature": "Bwd Packet Length Mean", "shap": -0.025, "val": 42.0, "rank": 5}
                ],
                # Geo & Threat Intel (synthetic for demo)
                "geo_country": "Russia", "geo_country_code": "RU",
                "geo_region": "Moscow", "geo_city": "Moscow",
                "geo_lat": 55.7558, "geo_lon": 37.6173,
                "geo_asn": 49505, "geo_asn_org": "Selectel Ltd.",
                "geo_is_synthetic": True,
                "ti_score": 87, "ti_reports": 342, "ti_is_known_bad": True,
                "ti_provider": "abuseipdb",
            },
            {
                "attack_class": "DoS Hulk",
                "ml_confidence": 0.932,
                "source_ip": "192.168.10.52",
                "dest_ip": "10.0.0.10",
                "dest_port": 80,
                "protocol": "TCP",
                "time_offset_mins": 34,
                "mitre_id": "T1499",
                "mitre_name": "Endpoint Denial of Service",
                "mitre_tactic": "Impact",
                "mitre_severity": "High",
                "mitre_desc": "Adversaries may perform Endpoint Denial of Service (DoS) attacks against web servers or services.",
                "asset_crit": 0.95,
                "risk_score": 0.88,
                "status": "new",
                "features": {
                    "fwd_pkt_len_mean": 850.0,
                    "flow_duration": 0.015,
                    "flow_pkts_per_sec": 12800.0,
                    "bwd_pkt_len_mean": 120.0,
                    "syn_flag_count": 0,
                    "flow_bytes_per_sec": 10880000.0
                },
                "shap": [
                    {"feature": "Flow Packets/s", "shap": 0.340, "val": 12800.0, "rank": 1},
                    {"feature": "Fwd Packet Length Mean", "shap": 0.260, "val": 850.0, "rank": 2},
                    {"feature": "Flow Duration", "shap": 0.140, "val": 0.015, "rank": 3},
                    {"feature": "Bwd Packet Length Mean", "shap": -0.010, "val": 120.0, "rank": 4}
                ],
                "geo_country": "China", "geo_country_code": "CN",
                "geo_region": "Beijing", "geo_city": "Beijing",
                "geo_lat": 39.9042, "geo_lon": 116.4074,
                "geo_asn": 4134, "geo_asn_org": "China Telecom",
                "geo_is_synthetic": True,
                "ti_score": 72, "ti_reports": 198, "ti_is_known_bad": True,
                "ti_provider": "abuseipdb",
            },
            {
                "attack_class": "SSH-Patator",
                "ml_confidence": 0.915,
                "source_ip": "192.168.10.14",
                "dest_ip": "10.0.0.15",
                "dest_port": 22,
                "protocol": "TCP",
                "time_offset_mins": 62,
                "mitre_id": "T1110",
                "mitre_name": "Brute Force",
                "mitre_tactic": "Credential Access",
                "mitre_severity": "High",
                "mitre_desc": "Adversaries may use brute force credential guessing against authentication protocols such as SSH.",
                "asset_crit": 0.85,
                "risk_score": 0.84,
                "status": "investigating",
                "features": {
                    "fwd_pkt_len_mean": 88.0,
                    "flow_duration": 4.25,
                    "flow_pkts_per_sec": 12.4,
                    "bwd_pkt_len_mean": 112.0,
                    "syn_flag_count": 1,
                    "flow_bytes_per_sec": 2480.0
                },
                "shap": [
                    {"feature": "Dst Port (22/SSH)", "shap": 0.410, "val": 22.0, "rank": 1},
                    {"feature": "Flow Duration", "shap": 0.220, "val": 4.25, "rank": 2},
                    {"feature": "Fwd Packet Length Mean", "shap": 0.180, "val": 88.0, "rank": 3},
                    {"feature": "Flow Packets/s", "shap": -0.040, "val": 12.4, "rank": 4}
                ],
                "geo_country": "Romania", "geo_country_code": "RO",
                "geo_region": "Bucharest", "geo_city": "Bucharest",
                "geo_lat": 44.4268, "geo_lon": 26.1025,
                "geo_asn": 9009, "geo_asn_org": "M247 Europe SRL",
                "geo_is_synthetic": True,
                "ti_score": 93, "ti_reports": 528, "ti_is_known_bad": True,
                "ti_provider": "abuseipdb",
            },
            {
                "attack_class": "PortScan",
                "ml_confidence": 0.890,
                "source_ip": "192.168.10.99",
                "dest_ip": "10.0.0.25",
                "dest_port": 445,
                "protocol": "TCP",
                "time_offset_mins": 95,
                "mitre_id": "T1046",
                "mitre_name": "Network Service Discovery",
                "mitre_tactic": "Discovery",
                "mitre_severity": "Medium",
                "mitre_desc": "Adversaries may attempt to get a listing of services running on hosts through port scanning techniques.",
                "asset_crit": 0.60,
                "risk_score": 0.68,
                "status": "new",
                "features": {
                    "fwd_pkt_len_mean": 0.0,
                    "flow_duration": 0.00012,
                    "flow_pkts_per_sec": 16666.0,
                    "bwd_pkt_len_mean": 0.0,
                    "syn_flag_count": 1,
                    "flow_bytes_per_sec": 0.0
                },
                "shap": [
                    {"feature": "SYN Flag Count", "shap": 0.350, "val": 1.0, "rank": 1},
                    {"feature": "Fwd Packet Length Mean", "shap": -0.210, "val": 0.0, "rank": 2},
                    {"feature": "Flow Duration", "shap": 0.290, "val": 0.00012, "rank": 3},
                    {"feature": "Bwd Packet Length Mean", "shap": -0.120, "val": 0.0, "rank": 4}
                ],
                "geo_country": "Netherlands", "geo_country_code": "NL",
                "geo_region": "North Holland", "geo_city": "Amsterdam",
                "geo_lat": 52.3676, "geo_lon": 4.9041,
                "geo_asn": 60781, "geo_asn_org": "LeaseWeb Netherlands B.V.",
                "geo_is_synthetic": True,
                "ti_score": 45, "ti_reports": 89, "ti_is_known_bad": False,
                "ti_provider": "abuseipdb",
            },
            {
                "attack_class": "Web Attack",
                "ml_confidence": 0.880,
                "source_ip": "192.168.10.88",
                "dest_ip": "10.0.0.10",
                "dest_port": 80,
                "protocol": "TCP",
                "time_offset_mins": 140,
                "mitre_id": "T1190",
                "mitre_name": "Exploit Public-Facing Application",
                "mitre_tactic": "Initial Access",
                "mitre_severity": "High",
                "mitre_desc": "Adversaries may attempt to exploit a vulnerability in an Internet-facing application (SQLi, XSS).",
                "asset_crit": 0.95,
                "risk_score": 0.86,
                "status": "new",
                "features": {
                    "fwd_pkt_len_mean": 480.0,
                    "flow_duration": 0.045,
                    "flow_pkts_per_sec": 44.0,
                    "bwd_pkt_len_mean": 1280.0,
                    "syn_flag_count": 0,
                    "flow_bytes_per_sec": 77440.0
                },
                "shap": [
                    {"feature": "Fwd Packet Length Mean", "shap": 0.320, "val": 480.0, "rank": 1},
                    {"feature": "Bwd Packet Length Mean", "shap": 0.250, "val": 1280.0, "rank": 2},
                    {"feature": "Flow Packets/s", "shap": 0.120, "val": 44.0, "rank": 3}
                ],
                "geo_country": "Brazil", "geo_country_code": "BR",
                "geo_region": "São Paulo", "geo_city": "São Paulo",
                "geo_lat": -23.5505, "geo_lon": -46.6333,
                "geo_asn": 28573, "geo_asn_org": "Claro S.A.",
                "geo_is_synthetic": True,
                "ti_score": 61, "ti_reports": 147, "ti_is_known_bad": True,
                "ti_provider": "abuseipdb",
            },
            {
                "attack_class": "FTP-Patator",
                "ml_confidence": 0.875,
                "source_ip": "192.168.10.19",
                "dest_ip": "10.0.0.20",
                "dest_port": 21,
                "protocol": "TCP",
                "time_offset_mins": 190,
                "mitre_id": "T1110",
                "mitre_name": "Brute Force",
                "mitre_tactic": "Credential Access",
                "mitre_severity": "High",
                "mitre_desc": "Adversaries may use brute force credential guessing against authentication protocols such as FTP.",
                "asset_crit": 0.70,
                "risk_score": 0.77,
                "status": "new",
                "features": {
                    "fwd_pkt_len_mean": 45.0,
                    "flow_duration": 1.85,
                    "flow_pkts_per_sec": 8.5,
                    "bwd_pkt_len_mean": 64.0,
                    "syn_flag_count": 1,
                    "flow_bytes_per_sec": 926.5
                },
                "shap": [
                    {"feature": "Dst Port (21/FTP)", "shap": 0.390, "val": 21.0, "rank": 1},
                    {"feature": "Flow Duration", "shap": 0.240, "val": 1.85, "rank": 2},
                    {"feature": "Fwd Packet Length Mean", "shap": 0.130, "val": 45.0, "rank": 3}
                ],
                "geo_country": "India", "geo_country_code": "IN",
                "geo_region": "Maharashtra", "geo_city": "Mumbai",
                "geo_lat": 19.0760, "geo_lon": 72.8777,
                "geo_asn": 55836, "geo_asn_org": "Reliance Jio Infocomm Limited",
                "geo_is_synthetic": True,
                "ti_score": 38, "ti_reports": 54, "ti_is_known_bad": False,
                "ti_provider": "abuseipdb",
            },
            {
                "attack_class": "Botnet",
                "ml_confidence": 0.845,
                "source_ip": "10.0.0.45",
                "dest_ip": "198.51.100.22",
                "dest_port": 8080,
                "protocol": "TCP",
                "time_offset_mins": 260,
                "mitre_id": "T1071",
                "mitre_name": "Application Layer Protocol",
                "mitre_tactic": "Command and Control",
                "mitre_severity": "High",
                "mitre_desc": "Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
                "asset_crit": 0.70,
                "risk_score": 0.76,
                "status": "investigating",
                "features": {
                    "fwd_pkt_len_mean": 210.0,
                    "flow_duration": 60.5,
                    "flow_pkts_per_sec": 0.45,
                    "bwd_pkt_len_mean": 180.0,
                    "syn_flag_count": 1,
                    "flow_bytes_per_sec": 175.5
                },
                "shap": [
                    {"feature": "Flow Duration", "shap": 0.360, "val": 60.5, "rank": 1},
                    {"feature": "Dst Port", "shap": 0.210, "val": 8080.0, "rank": 2},
                    {"feature": "Flow Packets/s", "shap": -0.150, "val": 0.45, "rank": 3}
                ],
                "geo_country": "Ukraine", "geo_country_code": "UA",
                "geo_region": "Kyiv", "geo_city": "Kyiv",
                "geo_lat": 50.4501, "geo_lon": 30.5234,
                "geo_asn": 13188, "geo_asn_org": "Content Delivery Network Ltd",
                "geo_is_synthetic": True,
                "ti_score": 78, "ti_reports": 267, "ti_is_known_bad": True,
                "ti_provider": "abuseipdb",
            },
            {
                "attack_class": "Infiltration",
                "ml_confidence": 0.810,
                "source_ip": "10.0.0.32",
                "dest_ip": "10.0.0.5",
                "dest_port": 445,
                "protocol": "TCP",
                "time_offset_mins": 380,
                "mitre_id": "T1059",
                "mitre_name": "Command and Scripting Interpreter",
                "mitre_tactic": "Execution",
                "mitre_severity": "Critical",
                "mitre_desc": "Adversaries may abuse command and script interpreters to execute arbitrary commands, scripts, or binaries.",
                "asset_crit": 0.90,
                "risk_score": 0.83,
                "status": "new",
                "features": {
                    "fwd_pkt_len_mean": 620.0,
                    "flow_duration": 12.4,
                    "flow_pkts_per_sec": 3.8,
                    "bwd_pkt_len_mean": 940.0,
                    "syn_flag_count": 1,
                    "flow_bytes_per_sec": 5928.0
                },
                "shap": [
                    {"feature": "Dst Port (445/SMB)", "shap": 0.350, "val": 445.0, "rank": 1},
                    {"feature": "Bwd Packet Length Mean", "shap": 0.280, "val": 940.0, "rank": 2},
                    {"feature": "Fwd Packet Length Mean", "shap": 0.190, "val": 620.0, "rank": 3}
                ],
                "geo_country": "United States", "geo_country_code": "US",
                "geo_region": "Virginia", "geo_city": "Ashburn",
                "geo_lat": 39.0438, "geo_lon": -77.4874,
                "geo_asn": 14618, "geo_asn_org": "Amazon.com Inc.",
                "geo_is_synthetic": True,
                "ti_score": 12, "ti_reports": 8, "ti_is_known_bad": False,
                "ti_provider": "abuseipdb",
            },
            {
                "attack_class": "Benign",
                "ml_confidence": 0.992,
                "source_ip": "10.0.0.50",
                "dest_ip": "8.8.8.8",
                "dest_port": 53,
                "protocol": "UDP",
                "time_offset_mins": 420,
                "mitre_id": None,
                "mitre_name": None,
                "mitre_tactic": None,
                "mitre_severity": "Low",
                "mitre_desc": None,
                "asset_crit": 0.30,
                "risk_score": 0.12,
                "status": "closed",
                "features": {
                    "fwd_pkt_len_mean": 36.0,
                    "flow_duration": 0.012,
                    "flow_pkts_per_sec": 166.0,
                    "bwd_pkt_len_mean": 84.0,
                    "syn_flag_count": 0,
                    "flow_bytes_per_sec": 19920.0
                },
                "shap": [
                    {"feature": "Flow Packets/s", "shap": -0.320, "val": 166.0, "rank": 1},
                    {"feature": "Fwd Packet Length Mean", "shap": -0.280, "val": 36.0, "rank": 2},
                    {"feature": "Flow Duration", "shap": -0.150, "val": 0.012, "rank": 3}
                ],
                "geo_country": "United States", "geo_country_code": "US",
                "geo_region": "California", "geo_city": "Mountain View",
                "geo_lat": 37.3861, "geo_lon": -122.0839,
                "geo_asn": 15169, "geo_asn_org": "Google LLC",
                "geo_is_synthetic": True,
                "ti_score": 0, "ti_reports": 0, "ti_is_known_bad": False,
                "ti_provider": "abuseipdb",
            }
        ]

        created_alerts = []
        for d in sample_alerts_data:
            alt_id = str(uuid.uuid4())
            det_time = now - timedelta(minutes=d["time_offset_mins"])
            
            components = {
                "ml_confidence": d["ml_confidence"],
                "asset_criticality": d["asset_crit"],
                "attack_severity": 0.9 if d["mitre_severity"] == "High" else (1.0 if d["mitre_severity"] == "Critical" else 0.5),
                "threat_intel": (d.get("ti_score", 0) or 0) / 100.0,
            }

            alt = Alert(
                id=alt_id,
                detected_at=det_time,
                source_ip=d["source_ip"],
                dest_ip=d["dest_ip"],
                dest_port=d["dest_port"],
                protocol=d["protocol"],
                flow_features=d["features"],
                attack_class=d["attack_class"],
                ml_confidence=d["ml_confidence"],
                class_probabilities={d["attack_class"]: d["ml_confidence"]},
                mitre_technique_id=d["mitre_id"],
                mitre_technique_name=d["mitre_name"],
                mitre_tactic=d["mitre_tactic"],
                mitre_severity=d["mitre_severity"],
                mitre_description=d["mitre_desc"],
                asset_criticality=d["asset_crit"],
                risk_score=d["risk_score"],
                risk_score_components=components,
                # Geolocation
                geo_source_country=d.get("geo_country"),
                geo_source_country_code=d.get("geo_country_code"),
                geo_source_region=d.get("geo_region"),
                geo_source_city=d.get("geo_city"),
                geo_source_lat=d.get("geo_lat"),
                geo_source_lon=d.get("geo_lon"),
                geo_source_asn=d.get("geo_asn"),
                geo_source_asn_org=d.get("geo_asn_org"),
                geo_is_synthetic=d.get("geo_is_synthetic", True),
                # Threat Intel
                threat_intel_score=d.get("ti_score"),
                threat_intel_reports=d.get("ti_reports"),
                threat_intel_is_known_bad=d.get("ti_is_known_bad", False),
                threat_intel_provider=d.get("ti_provider"),
                # Status
                status=d["status"],
                ingested_at=det_time + timedelta(seconds=2)
            )
            db.add(alt)
            created_alerts.append(alt)

            # Add SHAP features
            for sf in d["shap"]:
                feat = AlertShapFeature(
                    id=str(uuid.uuid4()),
                    alert_id=alt_id,
                    feature_name=sf["feature"],
                    shap_value=sf["shap"],
                    feature_value=sf["val"],
                    rank=sf["rank"]
                )
                db.add(feat)

        db.commit()

        # 3. Seed Initial Incident Cases
        if created_alerts:
            # Case 1: Ingress DDoS Incident
            ddos_alerts = [a for a in created_alerts if a.attack_class in ["DDoS", "DoS Hulk"]]
            if ddos_alerts:
                case1 = Case(
                    id=str(uuid.uuid4()),
                    title="INC-2025-001: Volumetric DDoS Attack Targeting Web DMZ",
                    status="investigating",
                    severity="critical",
                    assigned_to="analyst",
                    notes="High packet-rate ingress anomaly observed on DMZ Web Server (10.0.0.10). SHAP indicators confirm anomalous forward packet sizes and short flow durations typical of syn/flood amplification. Source IPs geolocated to Russia (Moscow) and China (Beijing) — both flagged as known-bad by AbuseIPDB (scores: 87, 72).",
                    disposition="true_positive",
                    created_at=now - timedelta(minutes=25),
                    updated_at=now - timedelta(minutes=5)
                )
                case1.alerts = ddos_alerts
                db.add(case1)

            # Case 2: Bastion Brute Force
            ssh_alerts = [a for a in created_alerts if a.attack_class in ["SSH-Patator", "FTP-Patator"]]
            if ssh_alerts:
                case2 = Case(
                    id=str(uuid.uuid4()),
                    title="INC-2025-002: Repeated Authentication Brute Force on Internal Bastion",
                    status="open",
                    severity="high",
                    assigned_to="analyst",
                    notes="Persistent dictionary attack detected targeting port 22 and port 21 from 192.168.10.x subnet. SSH source IP geolocated to Romania (Bucharest, ASN: M247) — a known bulletproof hosting provider with abuse score 93/100. Rate limiting advised.",
                    disposition="undetermined",
                    created_at=now - timedelta(minutes=55),
                    updated_at=now - timedelta(minutes=50)
                )
                case2.alerts = ssh_alerts
                db.add(case2)

            db.commit()
