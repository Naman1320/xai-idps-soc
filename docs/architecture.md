# System Architecture — XAI-IDPS-SOC

## Overview

**XAI-IDPS-SOC** bridges the fundamental divide between academic ML-based intrusion detection systems (which output raw class labels and stop at offline evaluation) and operational Security Operations Centers (which require context, actionable explainability, and transparent risk scoring).

```
┌────────────────────────────────────────────────────────────────────────┐
│                      DETECTION & SENSOR ENGINE                         │
│                                                                        │
│   Network Flows (CSE-CIC-IDS2018 / CICIDS2017 / UNSW-NB15)             │
│                              │                                         │
│                              ▼                                         │
│                [ Data Preprocessing & Scaler ]                         │
│                              │                                         │
│                              ▼                                         │
│            [ Machine Learning Classifier (RF / XGB) ]                  │
│                              │                                         │
│         ┌────────────────────┴────────────────────┐                    │
│         ▼                                         ▼                    │
│   Class & Confidence                      [ SHAP TreeExplainer ]       │
│         │                                 Local Feature Attribution    │
│         │                                         │                    │
│         └────────────────────┬────────────────────┘                    │
│                              │                                         │
│                              ▼                                         │
│                 [ Alert Enrichment Pipeline ]                          │
│                   • MITRE ATT&CK Mapping (Enterprise Matrix)           │
│                   • Asset Inventory Criticality (Context Engine)       │
│                   • Geolocation Enrichment (MaxMind GeoLite2)          │
│                   • Threat Intelligence Lookup (AbuseIPDB Free Tier)   │
│                   • Extended 4-Weight Composite Risk Scoring           │
│                              │                                         │
│                              ▼                                         │
│                   Normalized Alert JSON (Enriched)                     │
└──────────────────────────────┼─────────────────────────────────────────┘
                               │
                               │ HTTPS REST API POST /api/v1/alerts
                               │ (X-API-Key: Machine-to-Machine)
                               ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        CLOUD SOC PLATFORM                              │
│                                                                        │
│   [ FastAPI Backend ]                                                  │
│     ├── Ingestion & Validation Middleware                              │
│     ├── Geolocation API Router (/api/v1/geo/alerts-map, summaries)     │
│     ├── SQLAlchemy ORM (PostgreSQL / SQLite)                           │
│     ├── Automated IPS Prevention Engine (iptables DROP rules)          │
│     ├── Digital Twin Network Topology Engine                           │
│     ├── AI SOC Copilot (Investigation & Triage Summaries)              │
│     ├── Ground-Truth Feedback Loop                                     │
│     └── Exportable SOC Shift Handover & Viva Reporting                 │
│                                                                        │
│   [ React SOC Analyst Dashboard ]                                      │
│     ├── Alert Queue (Sorted by Composite Risk Score)                   │
│     ├── SHAP Waterfall Chart (Client-Side Rendering)                   │
│     ├── MITRE ATT&CK Technique Cards & Matrices                        │
│     ├── Interactive Geo Map (Leaflet Dark CARTO Tiles + Markers)       │
│     ├── Digital Twin Topology (Simulated Node Attacks & Active Blocks) │
│     ├── Incident Case Management & Investigation Notes                 │
│     └── Interactive Risk Calibration (w1, w2, w3, w4 Sliders)          │
└────────────────────────────────────────────────────────────────────────┘
```

---

## The Pipeline Contract

To guarantee that explainability and context are never lost during transport from sensor to cloud dashboard, all alerts conform to the strict JSON schema:

```json
{
  "alert_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "timestamp": "2026-09-22T12:00:00Z",
  "source_ip": "192.168.10.45",
  "dest_ip": "10.0.0.10",
  "dest_port": 80,
  "protocol": "TCP",
  "flow_features": {
    "flow_duration": 0.0028,
    "fwd_pkt_len_mean": 1420.5,
    "flow_pkts_per_sec": 35714.2
  },
  "classification": {
    "attack_class": "DDoS",
    "confidence": 0.965,
    "probabilities": { "Benign": 0.035, "DDoS": 0.965 }
  },
  "shap_explanation": {
    "base_value": 0.10,
    "feature_contributions": [
      { "feature": "Flow Packets/s", "shap_value": 0.385, "feature_value": 35714.2, "rank": 1 },
      { "feature": "Fwd Packet Length Mean", "shap_value": 0.285, "feature_value": 1420.5, "rank": 2 }
    ]
  },
  "mitre_mapping": {
    "technique_id": "T1498",
    "technique_name": "Network Denial of Service",
    "tactic": "Impact",
    "severity": "High"
  },
  "geo_context": {
    "source": {
      "country": "Russia",
      "country_code": "RU",
      "region": "Moscow",
      "city": "Moscow",
      "latitude": 55.7558,
      "longitude": 37.6173,
      "asn": 49505,
      "asn_org": "Selectel Ltd.",
      "is_private": false,
      "is_synthetic": true,
      "accuracy_caveat": "City-level accuracy only; unreliable for VPN/proxy/CGNAT"
    }
  },
  "threat_intel": {
    "source_ip": {
      "abuse_confidence_score": 87,
      "total_reports": 342,
      "is_known_bad": true,
      "provider": "abuseipdb"
    }
  },
  "risk_score": {
    "composite": 0.91,
    "components": {
      "ml_confidence": 0.965,
      "asset_criticality": 0.95,
      "attack_severity": 0.90,
      "threat_intel": 0.87
    },
    "weights": { "w1": 0.45, "w2": 0.25, "w3": 0.15, "w4": 0.15 }
  }
}
```

---

## Transparent 4-Weight Composite Risk Scoring

Commercial SIEMs use proprietary black-box scoring. This system uses an explicit, documented, and tunable formula:

$$\text{Risk Score} = w_1 \times \text{ML\_Confidence} + w_2 \times \text{Asset\_Criticality} + w_3 \times \text{ATT\&CK\_Severity} + w_4 \times \text{Threat\_Intel\_Score}$$

Where:
- $w_1 = 0.45$: ML classifier probability score (RF / XGBoost with SHAP).
- $w_2 = 0.25$: Asset criticality rating (Domain Controller = 0.95, Web Server = 0.90, Dev node = 0.60).
- $w_3 = 0.15$: MITRE ATT&CK technique severity rating (Impact/Exfiltration = 0.90, Discovery = 0.50).
- $w_4 = 0.15$: Threat intelligence reputation score (AbuseIPDB confidence / 100).
- Constraint: $w_1 + w_2 + w_3 + w_4 = 1.0$.

---

## Research Framing & Analytical Caveats

1. **Threat-Intel Reputation as Detection Input**:
   - AbuseIPDB reputation scores and ASN profiling provide legitimate research contribution as an active input to triage scoring ($w_4$).
   - Alerts originating from known-bad infrastructure or bulletproof ASNs receive higher priority.

2. **IP Geolocation Limitations**:
   - City-level geolocation is inherently approximate (~55–80% accuracy).
   - Easily bypassed or distorted by commercial VPNs, Tor exit nodes, proxies, and carrier-grade NAT (CGNAT).
   - In benchmark datasets (CSE-CIC-IDS2018), network flows are captured in controlled lab environments using private RFC 1918 addresses; coordinates are generated synthetically for demonstration purposes and clearly tagged (`geo_is_synthetic = true`).
   - Consequently, geolocation is presented as an auxiliary contextual visualization rather than definitive proof of adversarial attribution.
