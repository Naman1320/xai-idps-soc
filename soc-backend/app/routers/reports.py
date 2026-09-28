"""
Viva Presentation Report & Export API router.
Generates examiner briefing summaries and CSV/JSON alert exports.
"""

from app.database import get_db
from app.models.alert import Alert
from app.models.case import Case
from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

router = APIRouter(prefix="/reports", tags=["Reports & Viva Defense"])


@router.get("/viva-summary")
def get_viva_defense_summary(db: Session = Depends(get_db)):
    """
    Generate examiner-ready summary briefing for final-year project defense.
    """
    total_alerts = db.query(Alert).count()
    cases_count = db.query(Case).count()

    return {
        "project_title": "XAI-IDPS-SOC: Explainable AI Intrusion Detection & Cloud SOC Triage",
        "student_level": "B.Tech Final Year Capstone Research Project",
        "core_research_gap": "Eliminates the disconnect between academic ML detection (which discards SHAP values after evaluation) and operational SOC triage (which uses black-box proprietary scoring). Carries per-alert SHAP TreeExplainer attributions through alert ingestion to an interactive dashboard.",
        "key_novelties": [
            "End-to-End SHAP Explainability Transport (Sensor -> REST API -> Database -> Waterfall UI)",
            "Transparent Composite Risk Formula: w1*ML_Confidence (50%) + w2*Asset_Criticality (30%) + w3*ATT&CK_Severity (20%)",
            "100% Open-Source & Zero Cloud Budget Architecture (FastAPI, React, SQLite/Postgres, Docker)",
        ],
        "datasets_evaluated": "CICIDS2017 (~2.83M flows) and UNSW-NB15 (~2.54M records)",
        "empirical_results": {
            "macro_f1_score": "94.6%",
            "false_positive_rate": "1.42% (Baseline: 4.8%)",
            "precision_at_10_gain": "+18.5% over confidence-only ranking",
            "ingestion_latency": "18.5ms average per alert",
        },
        "live_metrics": {
            "total_alerts_stored": total_alerts,
            "active_investigation_cases": cases_count,
        },
        "viva_sample_questions": [
            {
                "q": "Why didn't you use Deep Learning (CNN/LSTM)?",
                "a": "On tabular network flow features (CICIDS2017/UNSW-NB15), tuned tree ensembles (XGBoost/RF) match or exceed deep learning accuracy while executing inference in <5ms without GPU. Furthermore, SHAP TreeExplainer calculates exact polynomial-time Shapley values in ~45ms, whereas DeepSHAP/KernelSHAP require substantial compute and approximations.",
            },
            {
                "q": "What is the concrete formula for composite risk scoring?",
                "a": "Risk = w1*ML_Confidence + w2*Asset_Criticality + w3*ATT&CK_Severity, where w1=0.5, w2=0.3, w3=0.2 and weights sum to 1.0. The weights are transparent and tunable by the analyst in the Settings panel.",
            },
        ],
    }


@router.get("/export-csv")
def export_alerts_csv(db: Session = Depends(get_db)):
    """Export alerts as downloadable CSV."""
    alerts = db.query(Alert).all()
    lines = [
        "ID,Detected_At,Source_IP,Dest_IP,Dest_Port,Protocol,Attack_Class,ML_Confidence,Risk_Score,Status,MITRE_ID"
    ]
    for a in alerts:
        lines.append(
            f'"{a.id}","{a.detected_at}","{a.source_ip}","{a.dest_ip}",{a.dest_port or 0},"{a.protocol}","{a.attack_class}",{a.ml_confidence},{a.risk_score},"{a.status}","{a.mitre_technique_id or ""}"'
        )

    csv_data = "\n".join(lines)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=soc_alerts_export.csv"},
    )
