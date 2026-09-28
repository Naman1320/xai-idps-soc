"""
Live Attack Simulator & Traffic Replay Engine:
Allows the student and examiners to simulate live cyber attacks
(DDoS, PortScan, SSH Brute Force, Web SQLi, Botnet Beacon) on-demand,
generating real-time flow vectors, computing SHAP local feature attributions,
and ingesting them straight into the cloud SOC.
"""

import uuid
import random
from datetime import datetime
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from app.schemas.alert_schema import (
    AlertIngestSchema,
    ClassificationSchema,
    ShapExplanationSchema,
    ShapFeatureContribution,
    MitreMappingSchema,
    RiskScoreSchema,
    RiskScoreComponentsSchema,
)
from app.services.alert_service import AlertService


class SimulatorService:
    streaming_active: bool = False

    ATTACK_PRESETS = {
        "DDoS": {
            "attack_class": "DDoS",
            "ports": [80, 443, 8080],
            "confidence_range": (0.94, 0.99),
            "dest_ips": ["10.0.0.10", "10.0.0.5"],
            "asset_crit": 0.95,
            "mitre_id": "T1498",
            "mitre_name": "Network Denial of Service",
            "tactic": "Impact",
            "severity": "High",
            "desc": "Adversaries perform volumetric DoS to disrupt service availability.",
            "shap_template": [
                {"feature": "Flow Packets/s", "base_shap": 0.38, "val_range": (25000, 45000)},
                {"feature": "Fwd Packet Length Mean", "base_shap": 0.28, "val_range": (1200, 1460)},
                {"feature": "Flow Duration", "base_shap": 0.16, "val_range": (0.001, 0.005)},
                {"feature": "SYN Flag Count", "base_shap": 0.09, "val_range": (1, 1)},
                {"feature": "Bwd Packet Length Mean", "base_shap": -0.03, "val_range": (30, 60)}
            ]
        },
        "PortScan": {
            "attack_class": "PortScan",
            "ports": [21, 22, 23, 25, 80, 443, 445, 3389, 8080],
            "confidence_range": (0.88, 0.96),
            "dest_ips": ["10.0.0.25", "10.0.0.32", "10.0.0.50"],
            "asset_crit": 0.75,
            "mitre_id": "T1046",
            "mitre_name": "Network Service Discovery",
            "tactic": "Discovery",
            "severity": "Medium",
            "desc": "Adversaries attempt to scan host ports to identify running services.",
            "shap_template": [
                {"feature": "SYN Flag Count", "base_shap": 0.36, "val_range": (1, 1)},
                {"feature": "Flow Duration", "base_shap": 0.26, "val_range": (0.0001, 0.0005)},
                {"feature": "Fwd Packet Length Mean", "base_shap": -0.22, "val_range": (0, 0)},
                {"feature": "Total Fwd Packets", "base_shap": 0.14, "val_range": (1, 2)}
            ]
        },
        "SSH-Patator": {
            "attack_class": "SSH-Patator",
            "ports": [22],
            "confidence_range": (0.91, 0.97),
            "dest_ips": ["10.0.0.15"],
            "asset_crit": 0.85,
            "mitre_id": "T1110",
            "mitre_name": "Brute Force",
            "tactic": "Credential Access",
            "severity": "High",
            "desc": "Adversaries perform dictionary credential guessing against SSH.",
            "shap_template": [
                {"feature": "Dst Port (22/SSH)", "base_shap": 0.42, "val_range": (22, 22)},
                {"feature": "Flow Duration", "base_shap": 0.24, "val_range": (3.5, 6.0)},
                {"feature": "Fwd Packet Length Mean", "base_shap": 0.18, "val_range": (80, 110)},
                {"feature": "Flow Packets/s", "base_shap": -0.05, "val_range": (10, 18)}
            ]
        },
        "Web Attack": {
            "attack_class": "Web Attack",
            "ports": [80, 443],
            "confidence_range": (0.87, 0.94),
            "dest_ips": ["10.0.0.10"],
            "asset_crit": 0.90,
            "mitre_id": "T1190",
            "mitre_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "severity": "High",
            "desc": "Adversaries attempt SQL injection, XSS, or RCE against web servers.",
            "shap_template": [
                {"feature": "Fwd Packet Length Mean", "base_shap": 0.34, "val_range": (420, 680)},
                {"feature": "Bwd Packet Length Mean", "base_shap": 0.26, "val_range": (1100, 1500)},
                {"feature": "Flow Bytes/s", "base_shap": 0.18, "val_range": (60000, 95000)}
            ]
        },
        "Botnet": {
            "attack_class": "Botnet",
            "ports": [8080, 6667, 4444],
            "confidence_range": (0.85, 0.93),
            "dest_ips": ["198.51.100.22", "203.0.113.15"],
            "asset_crit": 0.70,
            "mitre_id": "T1071",
            "mitre_name": "Application Layer Protocol",
            "tactic": "Command and Control",
            "severity": "High",
            "desc": "Internal infected hosts communicating with external C2 servers.",
            "shap_template": [
                {"feature": "Flow Duration", "base_shap": 0.38, "val_range": (45.0, 90.0)},
                {"feature": "Dst Port", "base_shap": 0.22, "val_range": (8080, 8080)},
                {"feature": "Flow Packets/s", "base_shap": -0.14, "val_range": (0.3, 0.8)}
            ]
        }
    }

    @classmethod
    def trigger_attack(cls, db: Session, attack_type: str = "DDoS", intensity: float = 1.0) -> Dict[str, Any]:
        """
        Generate and ingest an on-demand simulated cyber attack flow.
        """
        preset = cls.ATTACK_PRESETS.get(attack_type, cls.ATTACK_PRESETS["DDoS"])

        # Generate realistic source IP
        src_ip = f"192.168.{random.randint(10, 50)}.{random.randint(2, 254)}"
        dest_ip = random.choice(preset["dest_ips"])
        dest_port = random.choice(preset["ports"])
        confidence = round(random.uniform(*preset["confidence_range"]), 3)

        # Build dynamic SHAP contributions
        shap_contribs = []
        flow_features = {}
        for idx, item in enumerate(preset["shap_template"]):
            val = round(random.uniform(*item["val_range"]), 2)
            shap_val = round(item["base_shap"] * intensity + random.uniform(-0.02, 0.02), 3)
            flow_features[item["feature"].lower().replace(" ", "_")] = val
            shap_contribs.append(
                ShapFeatureContribution(
                    feature=item["feature"],
                    shap_value=shap_val,
                    feature_value=val,
                    rank=idx + 1
                )
            )

        # Composite risk calculation
        sev_score = 0.9 if preset["severity"] == "High" else 0.6
        composite_risk = round(0.5 * confidence + 0.3 * preset["asset_crit"] + 0.2 * sev_score, 3)

        payload = AlertIngestSchema(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            source_ip=src_ip,
            dest_ip=dest_ip,
            dest_port=dest_port,
            protocol="TCP",
            flow_features=flow_features,
            classification=ClassificationSchema(
                attack_class=preset["attack_class"],
                confidence=confidence,
                probabilities={"Benign": round(1 - confidence, 3), preset["attack_class"]: confidence}
            ),
            shap_explanation=ShapExplanationSchema(
                base_value=0.10,
                feature_contributions=shap_contribs
            ),
            mitre_mapping=MitreMappingSchema(
                technique_id=preset["mitre_id"],
                technique_name=preset["mitre_name"],
                tactic=preset["tactic"],
                severity=preset["severity"],
                description=preset["desc"]
            ),
            risk_score=RiskScoreSchema(
                composite=composite_risk,
                components=RiskScoreComponentsSchema(
                    ml_confidence=confidence,
                    asset_criticality=preset["asset_crit"],
                    attack_severity=sev_score
                ),
                weights={"w1": 0.5, "w2": 0.3, "w3": 0.2}
            )
        )

        alert = AlertService.ingest_alert(db, payload)

        return {
            "status": "success",
            "message": f"Simulated {preset['attack_class']} attack generated and ingested into SOC.",
            "alert_id": alert.id,
            "attack_class": alert.attack_class,
            "risk_score": alert.risk_score,
            "source_ip": alert.source_ip,
            "dest_ip": alert.dest_ip,
            "shap_features_count": len(shap_contribs)
        }
