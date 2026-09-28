# XAI-IDPS-SOC

**An Explainable Machine Learning-Based Intrusion Detection System Integrated with a Context-Enriched, MITRE ATT&CK-Mapped Cloud SOC Triage Platform**

## Overview

XAI-IDPS-SOC bridges the gap between ML-based intrusion detection research and SOC analyst workflows. It carries per-alert SHAP explanations from the detection engine through MITRE ATT&CK mapping, network asset criticality, source-IP geolocation enrichment, threat-intel reputation scoring, and composite risk scoring into an analyst-facing triage dashboard — as one cohesive, open-source pipeline.

## Architecture

```
Network Flows → ML Detection (RF/XGBoost) → SHAP TreeExplainer
    → MITRE ATT&CK Mapping → Asset Context Engine
    → Geolocation (MaxMind GeoLite2) + Threat-Intel (AbuseIPDB)
    → Transparent 4-Weight Composite Risk Scoring (w1·ML + w2·Asset + w3·ATT&CK + w4·Threat_Intel)
    → REST API Ingestion → Cloud SOC Backend (FastAPI + SQLite/Postgres)
    → Modern SOC Dashboard (Alert Queue, SHAP Waterfall, Incident Cases, Geo Map, Digital Twin, AI Copilot)
```

## Critical Research Framing: Threat-Intel vs. Geolocation

| Component | Role in Platform | Research Value vs. UI Feature | Accuracy & Limitations |
|-----------|------------------|-------------------------------|------------------------|
| **Threat-Intel (AbuseIPDB)** | **Detection / Triage Input (`w4`)** | **High Research Value**: Weights alert severity by crowd-sourced reputation confidence. A brute force attempt from an IP with 500 reports genuinely elevates triage priority. | Free tier (1,000 checks/day). Subject to crowd-sourcing bias and temporary rate limits; local cache utilized. |
| **ASN Profiling** | **Detection / Triage Input** | **High Research Value**: Flags traffic originating from bulletproof hosting providers or abuse-heavy ASNs. | Curated list of high-risk ASNs. |
| **Geolocation (MaxMind)** | **Dashboard Map View** | **Contextual UI / Visual Nicety**: Visualizes geographic alert origin on an interactive world map. | **Caveat**: City-level accuracy (~55–80%), easily defeated by VPNs, Tor, proxies, and CGNAT. Lab dataset IPs (RFC 1918) use synthetic coordinates for demonstration. |

## Datasets & Open Sources (100% Public)

- **CSE-CIC-IDS2018** (Primary): AWS Open Data `s3://cse-cic-ids2018/` — ~16M flows across 10 days, 7 attack scenarios. No signup required (`--no-sign-request`).
- **CICIDS2017**: ~2.83M flows, 84 features, 7 attack families.
- **UNSW-NB15**: ~2.54M records, 49 features, 9 attack categories.
- **MaxMind GeoLite2**: Free City and ASN `.mmdb` databases ([Free Signup](https://www.maxmind.com/en/geolite2/signup)).
- **AbuseIPDB Free Tier**: 1,000 free IP reputation checks/day ([Free API Key](https://www.abuseipdb.com/register)).

## Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+ (for dashboard)
- Docker & Docker Compose (optional, for containerized deployment)

### 1. Detection Engine Setup
```bash
cd detection
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt

# Download CSE-CIC-IDS2018 (AWS Open Data) or CICIDS2017
python scripts/download_cic_ids2018.py --days wednesday thursday-1 friday-1
python scripts/preprocess_data.py --dataset cic_ids2018 --sample 0.1

# Train detection models
python scripts/train_model.py --model tuned_rf
python scripts/train_model.py --model xgboost

# Run end-to-end detection pipeline with Geo + Threat-Intel enrichment
python scripts/run_detection.py --model tuned_rf --dataset cic_ids2018 --limit 100 --forward
```

### 2. SOC Backend Setup
```bash
cd soc-backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
API docs available at `http://localhost:8000/docs`.

### 3. SOC Dashboard Setup
```bash
cd soc-dashboard
npm install
npm run dev
```
Dashboard available at `http://localhost:5173`. Features:
- 📊 **Main Overview**: KPIs, real-time alert triage stream, attack distribution.
- 🚨 **Alert Queue**: SHAP waterfall explanations, MITRE techniques, Geo & Threat-Intel badges.
- 🗺️ **Geo Map**: Leaflet interactive dark-mode map of global alert origins with caveat banners.
- 🌐 **Digital Twin**: Interactive network topology graph with automated IPS containment.
- 📁 **Incident Cases**: Case management, analyst notes, MITRE ATT&CK breakdown.
- ⚙️ **Platform Settings**: Live 4-weight transparent risk calibration sliders (`w1` through `w4`).

### Docker Compose (Full Stack)
```bash
docker-compose up --build
```

## License
MIT

## Citation
```bibtex
@software{xai_idps_soc_2026,
  title={XAI-IDPS-SOC: Explainable ML-IDS with Geolocation, Threat-Intel, and Cloud SOC Triage},
  year={2026}
}
```
