"""
Alert and SHAP feature explanation ORM models.
Stores enriched intrusion detection alerts with explainability data,
geolocation context, and threat intelligence reputation scores.
"""

import uuid
from datetime import datetime

from app.database import Base
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
)
from sqlalchemy.orm import relationship


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    detected_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    dest_ip = Column(String(45), nullable=False, index=True)
    dest_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)
    flow_features = Column(JSON, nullable=True)  # Key-value flow metrics

    # ML Detection fields
    attack_class = Column(String(50), nullable=False, index=True)
    ml_confidence = Column(Float, nullable=False)
    class_probabilities = Column(JSON, nullable=True)

    # MITRE ATT&CK Enrichment
    mitre_technique_id = Column(String(20), nullable=True, index=True)
    mitre_technique_name = Column(String(200), nullable=True)
    mitre_tactic = Column(String(50), nullable=True)
    mitre_severity = Column(String(20), nullable=True)
    mitre_description = Column(String(500), nullable=True)

    # Asset Context & Composite Risk Scoring
    asset_criticality = Column(Float, default=0.5)
    risk_score = Column(Float, nullable=False, index=True)
    risk_score_components = Column(JSON, nullable=True)

    # Geolocation Context (MaxMind GeoLite2)
    # Caveat: City/region-level accuracy only; unreliable for VPN/proxy/CGNAT
    geo_source_country = Column(String(100), nullable=True, index=True)
    geo_source_country_code = Column(String(3), nullable=True)
    geo_source_region = Column(String(100), nullable=True)
    geo_source_city = Column(String(100), nullable=True)
    geo_source_lat = Column(Float, nullable=True)
    geo_source_lon = Column(Float, nullable=True)
    geo_source_asn = Column(Integer, nullable=True)
    geo_source_asn_org = Column(String(200), nullable=True)
    geo_is_synthetic = Column(Boolean, default=False)  # True for lab/private IPs

    # Threat Intelligence (AbuseIPDB)
    threat_intel_score = Column(Float, nullable=True)  # 0-100 abuse confidence
    threat_intel_reports = Column(Integer, nullable=True)  # total abuse reports
    threat_intel_is_known_bad = Column(Boolean, default=False)
    threat_intel_provider = Column(String(50), nullable=True)

    # Workflow Status: new, investigating, resolved, dismissed, closed
    status = Column(String(20), default="new", index=True)
    ingested_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Dataset Source & Topology Domain
    dataset_source = Column(
        String(50), nullable=True, default="CIC-IDS2017", index=True
    )
    domain = Column(String(20), nullable=True, default="network", index=True)

    # Relationships
    shap_features = relationship(
        "AlertShapFeature", back_populates="alert", cascade="all, delete-orphan"
    )
    feedback_entries = relationship(
        "Feedback", back_populates="alert", cascade="all, delete-orphan"
    )
    cases = relationship("Case", secondary="case_alerts", back_populates="alerts")


class AlertShapFeature(Base):
    __tablename__ = "alert_shap_features"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_id = Column(
        String(36),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    feature_name = Column(String(100), nullable=False)
    shap_value = Column(Float, nullable=False)
    feature_value = Column(Float, nullable=True)
    rank = Column(Integer, nullable=False, default=1)

    alert = relationship("Alert", back_populates="shap_features")
