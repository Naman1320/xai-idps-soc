"""
Multi-Dataset Alert Ingestion & Population Service.

Seeds diverse, realistic alerts across all 5 benchmarks:
  1. CICIoT2023     (domain: iot)     - 105 IoT device topology, Mirai botnet, MQTT floods
  2. Edge-IIoTset   (domain: iiot)    - Industrial edge PLC/Modbus, ransomware, scanning
  3. NF-ToN-IoT-v3  (domain: iot)     - NetFlow v3 telemetry, DDoS, brute force
  4. IoMT-CareFlow  (domain: iomt)    - Healthcare infusion pump anomalies, cardiac telemetry spoofing
  5. CIC-IDS2017    (domain: network) - Enterprise perimeter network attacks

All mapped to the exact 8 canonical classes:
  Benign, DoS/DDoS, Recon, Spoofing, Brute Force, Web, Malware/Botnet/Mirai, APT/Other
"""

import random
import uuid
from datetime import datetime, timedelta

from app.database import SessionLocal
from app.models.alert import Alert, AlertShapFeature

DATASET_PROFILES = [
    {
        "dataset_source": "CICIoT2023",
        "domain": "iot",
        "model_name": "Random Forest (IoT Topology)",
        "alerts": [
            {
                "attack_class": "Malware/Botnet/Mirai",
                "ml_confidence": 0.968,
                "source_ip": "192.168.1.105",
                "dest_ip": "10.0.0.1",
                "dest_port": 23,
                "protocol": "TCP",
                "mitre_id": "T1584.005",
                "mitre_name": "Compromise Infrastructure: Botnet",
                "mitre_tactic": "Resource Development",
                "mitre_severity": "Critical",
                "mitre_desc": "Mirai botnet variant coordinating high-velocity IoT C2 beaconing and telnet exploitation.",
                "risk_score": 0.94,
                "shap": [
                    {
                        "feature": "flow_duration",
                        "val": 0.0012,
                        "shap": 0.38,
                        "rank": 1,
                    },
                    {"feature": "syn_count", "val": 42.0, "shap": 0.31, "rank": 2},
                    {"feature": "rate", "val": 15400.0, "shap": 0.22, "rank": 3},
                    {"feature": "tot_size", "val": 3400.0, "shap": 0.08, "rank": 4},
                ],
            },
            {
                "attack_class": "DoS/DDoS",
                "ml_confidence": 0.952,
                "source_ip": "192.168.1.188",
                "dest_ip": "10.0.0.50",
                "dest_port": 80,
                "protocol": "TCP",
                "mitre_id": "T1498",
                "mitre_name": "Network Denial of Service",
                "mitre_tactic": "Impact",
                "mitre_severity": "High",
                "mitre_desc": "Volumetric SYN flood saturating IoT gateway bandwidth.",
                "risk_score": 0.89,
                "shap": [
                    {"feature": "rate", "val": 28400.0, "shap": 0.44, "rank": 1},
                    {"feature": "syn_flag_number", "val": 1.0, "shap": 0.28, "rank": 2},
                    {"feature": "flow_duration", "val": 0.003, "shap": 0.15, "rank": 3},
                ],
            },
            {
                "attack_class": "Recon",
                "ml_confidence": 0.912,
                "source_ip": "192.168.1.72",
                "dest_ip": "10.0.0.12",
                "dest_port": 8080,
                "protocol": "TCP",
                "mitre_id": "T1046",
                "mitre_name": "Network Service Discovery",
                "mitre_tactic": "Discovery",
                "mitre_severity": "Medium",
                "mitre_desc": "Automated port scan enumerating connected IP cameras and smart sensors.",
                "risk_score": 0.68,
                "shap": [
                    {"feature": "syn_count", "val": 18.0, "shap": 0.32, "rank": 1},
                    {"feature": "duration", "val": 0.04, "shap": 0.21, "rank": 2},
                ],
            },
            {
                "attack_class": "Spoofing",
                "ml_confidence": 0.894,
                "source_ip": "192.168.1.15",
                "dest_ip": "192.168.1.1",
                "dest_port": 53,
                "protocol": "UDP",
                "mitre_id": "T1557.002",
                "mitre_name": "Adversary-in-the-Middle: ARP Cache Poisoning",
                "mitre_tactic": "Credential Access",
                "mitre_severity": "High",
                "mitre_desc": "ARP spoofing poisoning IoT gateway default route to intercept telemetry.",
                "risk_score": 0.82,
                "shap": [
                    {"feature": "rate", "val": 4200.0, "shap": 0.29, "rank": 1},
                    {"feature": "tot_size", "val": 1800.0, "shap": 0.21, "rank": 2},
                ],
            },
        ],
    },
    {
        "dataset_source": "Edge-IIoTset",
        "domain": "iiot",
        "model_name": "Random Forest (Edge-IIoT)",
        "alerts": [
            {
                "attack_class": "Malware/Botnet/Mirai",
                "ml_confidence": 0.975,
                "source_ip": "172.16.20.14",
                "dest_ip": "172.16.20.100",
                "dest_port": 502,
                "protocol": "TCP",
                "mitre_id": "T1486",
                "mitre_name": "Data Encrypted for Impact (Ransomware)",
                "mitre_tactic": "Impact",
                "mitre_severity": "Critical",
                "mitre_desc": "Industrial edge ransomware attempting to lock Modbus PLC controller configuration.",
                "risk_score": 0.96,
                "shap": [
                    {"feature": "tcp.flags.reset", "val": 1.0, "shap": 0.36, "rank": 1},
                    {"feature": "tcp.len", "val": 1420.0, "shap": 0.28, "rank": 2},
                    {
                        "feature": "http.content_length",
                        "val": 2400.0,
                        "shap": 0.19,
                        "rank": 3,
                    },
                ],
            },
            {
                "attack_class": "Web",
                "ml_confidence": 0.941,
                "source_ip": "172.16.20.55",
                "dest_ip": "172.16.20.10",
                "dest_port": 80,
                "protocol": "TCP",
                "mitre_id": "T1190",
                "mitre_name": "Exploit Public-Facing Application (SQLi)",
                "mitre_tactic": "Initial Access",
                "mitre_severity": "High",
                "mitre_desc": "SQL injection payload against SCADA supervisory web interface.",
                "risk_score": 0.86,
                "shap": [
                    {
                        "feature": "http.content_length",
                        "val": 1280.0,
                        "shap": 0.41,
                        "rank": 1,
                    },
                    {"feature": "tcp.flags.push", "val": 1.0, "shap": 0.25, "rank": 2},
                ],
            },
            {
                "attack_class": "Brute Force",
                "ml_confidence": 0.933,
                "source_ip": "172.16.20.88",
                "dest_ip": "172.16.20.2",
                "dest_port": 22,
                "protocol": "TCP",
                "mitre_id": "T1110",
                "mitre_name": "Brute Force: Password Guessing",
                "mitre_tactic": "Credential Access",
                "mitre_severity": "High",
                "mitre_desc": "Automated dictionary attack against Industrial Edge Gateway SSH root account.",
                "risk_score": 0.84,
                "shap": [
                    {"feature": "tcp.flags.ack", "val": 1.0, "shap": 0.35, "rank": 1},
                    {"feature": "tcp.len", "val": 96.0, "shap": 0.22, "rank": 2},
                ],
            },
        ],
    },
    {
        "dataset_source": "NF-ToN-IoT-v3",
        "domain": "iot",
        "model_name": "XGBoost (NetFlow v3)",
        "alerts": [
            {
                "attack_class": "DoS/DDoS",
                "ml_confidence": 0.948,
                "source_ip": "10.0.4.88",
                "dest_ip": "192.168.10.5",
                "dest_port": 80,
                "protocol": "TCP",
                "mitre_id": "T1498",
                "mitre_name": "Network Denial of Service",
                "mitre_tactic": "Impact",
                "mitre_severity": "High",
                "mitre_desc": "Volumetric NetFlow flow surge targeting IoT core cluster.",
                "risk_score": 0.91,
                "shap": [
                    {"feature": "IN_PKTS", "val": 128.0, "shap": 0.42, "rank": 1},
                    {
                        "feature": "SRC_TO_DST_AVG_THROUGHPUT",
                        "val": 45000.0,
                        "shap": 0.33,
                        "rank": 2,
                    },
                    {
                        "feature": "FLOW_DURATION_MILLISECONDS",
                        "val": 12.0,
                        "shap": 0.12,
                        "rank": 3,
                    },
                ],
            },
            {
                "attack_class": "APT/Other",
                "ml_confidence": 0.885,
                "source_ip": "10.0.4.19",
                "dest_ip": "192.168.10.15",
                "dest_port": 4444,
                "protocol": "TCP",
                "mitre_id": "T1071.001",
                "mitre_name": "Application Layer Protocol: Web Protocols",
                "mitre_tactic": "Command and Control",
                "mitre_severity": "Critical",
                "mitre_desc": "Advanced persistent threat stealth backdoor establishing interactive reverse shell.",
                "risk_score": 0.88,
                "shap": [
                    {"feature": "DURATION_IN", "val": 3500.0, "shap": 0.34, "rank": 1},
                    {
                        "feature": "LONGEST_FLOW_PKT",
                        "val": 1024.0,
                        "shap": 0.27,
                        "rank": 2,
                    },
                ],
            },
        ],
    },
    {
        "dataset_source": "IoMT-CareFlow",
        "domain": "iomt",
        "model_name": "LightGBM (Healthcare IoMT)",
        "alerts": [
            {
                "attack_class": "Spoofing",
                "ml_confidence": 0.957,
                "source_ip": "10.200.4.12",
                "dest_ip": "10.200.1.5",
                "dest_port": 8443,
                "protocol": "TCP",
                "mitre_id": "T1565.002",
                "mitre_name": "Data Manipulation: Transmitted Data Manipulation",
                "mitre_tactic": "Impact",
                "mitre_severity": "Critical",
                "mitre_desc": "Spoofed HL7 telemetry injecting altered patient vitals and dosage parameters into Smart Infusion Pump.",
                "risk_score": 0.98,
                "shap": [
                    {
                        "feature": "dosage_rate_deviation",
                        "val": 4.8,
                        "shap": 0.49,
                        "rank": 1,
                    },
                    {
                        "feature": "hl7_checksum_delta",
                        "val": 1.0,
                        "shap": 0.28,
                        "rank": 2,
                    },
                    {
                        "feature": "connection_jitter",
                        "val": 0.05,
                        "shap": 0.14,
                        "rank": 3,
                    },
                ],
            },
            {
                "attack_class": "DoS/DDoS",
                "ml_confidence": 0.938,
                "source_ip": "10.200.4.88",
                "dest_ip": "10.200.1.20",
                "dest_port": 443,
                "protocol": "TCP",
                "mitre_id": "T1499",
                "mitre_name": "Endpoint Denial of Service",
                "mitre_tactic": "Impact",
                "mitre_severity": "Critical",
                "mitre_desc": "Resource exhaustion flood targeting hospital telemetry central gateway, delaying cardiac monitors.",
                "risk_score": 0.95,
                "shap": [
                    {
                        "feature": "telemetry_request_rate",
                        "val": 850.0,
                        "shap": 0.45,
                        "rank": 1,
                    },
                    {
                        "feature": "keepalive_timeout_ratio",
                        "val": 0.88,
                        "shap": 0.31,
                        "rank": 2,
                    },
                ],
            },
            {
                "attack_class": "Recon",
                "ml_confidence": 0.892,
                "source_ip": "10.200.4.99",
                "dest_ip": "10.200.2.0",
                "dest_port": 104,
                "protocol": "TCP",
                "mitre_id": "T1046",
                "mitre_name": "Network Service Discovery (DICOM)",
                "mitre_tactic": "Discovery",
                "mitre_severity": "Medium",
                "mitre_desc": "Unauthorized sweep probing PACS imaging servers and radiology workstations on port 104.",
                "risk_score": 0.65,
                "shap": [
                    {
                        "feature": "dicom_echo_frequency",
                        "val": 45.0,
                        "shap": 0.36,
                        "rank": 1,
                    },
                    {
                        "feature": "subnet_fanout_ratio",
                        "val": 0.92,
                        "shap": 0.24,
                        "rank": 2,
                    },
                ],
            },
        ],
    },
    {
        "dataset_source": "CIC-IDS2017",
        "domain": "network",
        "model_name": "XGBoost Classifier",
        "alerts": [
            {
                "attack_class": "Brute Force",
                "ml_confidence": 0.945,
                "source_ip": "192.168.10.14",
                "dest_ip": "10.0.0.10",
                "dest_port": 22,
                "protocol": "TCP",
                "mitre_id": "T1110.001",
                "mitre_name": "Password Guessing: SSH-Patator",
                "mitre_tactic": "Credential Access",
                "mitre_severity": "High",
                "mitre_desc": "SSH credential brute force attempting rapid root logon on Linux gateway.",
                "risk_score": 0.85,
                "shap": [
                    {
                        "feature": "Flow Packets/s",
                        "val": 240.0,
                        "shap": 0.34,
                        "rank": 1,
                    },
                    {
                        "feature": "Bwd Packet Length Mean",
                        "val": 48.0,
                        "shap": 0.26,
                        "rank": 2,
                    },
                ],
            },
            {
                "attack_class": "Web",
                "ml_confidence": 0.921,
                "source_ip": "192.168.10.99",
                "dest_ip": "10.0.0.10",
                "dest_port": 80,
                "protocol": "TCP",
                "mitre_id": "T1059",
                "mitre_name": "Command and Scripting Interpreter (XSS)",
                "mitre_tactic": "Execution",
                "mitre_severity": "High",
                "mitre_desc": "Cross-site scripting reflection payload injected into web portal session token.",
                "risk_score": 0.79,
                "shap": [
                    {
                        "feature": "Fwd Packet Length Mean",
                        "val": 980.0,
                        "shap": 0.38,
                        "rank": 1,
                    },
                    {"feature": "Flow Duration", "val": 0.12, "shap": 0.22, "rank": 2},
                ],
            },
        ],
    },
]


def populate_multidataset_alerts():
    db = SessionLocal()
    now = datetime.utcnow()
    total_added = 0

    print("🚀 Seeding multi-dataset alerts into database...")

    for profile in DATASET_PROFILES:
        ds_name = profile["dataset_source"]
        dom = profile["domain"]

        for item in profile["alerts"]:
            # Check if similar alert already exists
            existing = (
                db.query(Alert)
                .filter(
                    Alert.source_ip == item["source_ip"],
                    Alert.attack_class == item["attack_class"],
                    Alert.dataset_source == ds_name,
                )
                .first()
            )

            if not existing:
                alt_id = str(uuid.uuid4())
                det_time = now - timedelta(minutes=random.randint(5, 720))

                alert = Alert(
                    id=alt_id,
                    detected_at=det_time,
                    source_ip=item["source_ip"],
                    dest_ip=item["dest_ip"],
                    dest_port=item["dest_port"],
                    protocol=item["protocol"],
                    flow_features={
                        "protocol": item["protocol"],
                        "port": item["dest_port"],
                    },
                    attack_class=item["attack_class"],
                    ml_confidence=item["ml_confidence"],
                    class_probabilities={item["attack_class"]: item["ml_confidence"]},
                    mitre_technique_id=item["mitre_id"],
                    mitre_technique_name=item["mitre_name"],
                    mitre_tactic=item["mitre_tactic"],
                    mitre_severity=item["mitre_severity"],
                    mitre_description=item["mitre_desc"],
                    asset_criticality=0.85,
                    risk_score=item["risk_score"],
                    risk_score_components={
                        "ml_confidence": item["ml_confidence"],
                        "asset_criticality": 0.85,
                        "attack_severity": 0.9
                        if item["mitre_severity"] == "High"
                        else 1.0,
                    },
                    status="new",
                    ingested_at=det_time + timedelta(seconds=1),
                    dataset_source=ds_name,
                    domain=dom,
                    geo_source_country="United States",
                    geo_source_city="Chicago",
                    geo_is_synthetic=True,
                )
                db.add(alert)
                db.flush()

                for sf in item["shap"]:
                    feat = AlertShapFeature(
                        id=str(uuid.uuid4()),
                        alert_id=alt_id,
                        feature_name=sf["feature"],
                        shap_value=sf["shap"],
                        feature_value=sf["val"],
                        rank=sf["rank"],
                    )
                    db.add(feat)

                total_added += 1

    # Also backfill any alerts that had NULL dataset_source or domain
    db.query(Alert).filter(Alert.dataset_source.is_(None)).update(
        {"dataset_source": "CIC-IDS2017"}, synchronize_session=False
    )
    db.query(Alert).filter(Alert.domain.is_(None)).update(
        {"domain": "network"}, synchronize_session=False
    )

    db.commit()
    db.close()
    print(
        f"✅ Successfully seeded {total_added} new multi-dataset alerts across network, iot, iomt, and iiot domains!"
    )


if __name__ == "__main__":
    populate_multidataset_alerts()
