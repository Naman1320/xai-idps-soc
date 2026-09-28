"""
Pydantic schemas for alert ingestion, listing, detail, explanations,
geolocation context, and threat intelligence data.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ShapFeatureContribution(BaseModel):
    feature: str
    shap_value: float
    feature_value: float | None = None
    rank: int | None = None


class ShapExplanationSchema(BaseModel):
    base_value: float | None = 0.0
    feature_contributions: list[ShapFeatureContribution] = []


class MitreMappingSchema(BaseModel):
    technique_id: str | None = None
    technique_name: str | None = None
    tactic: str | None = None
    severity: str | None = None
    description: str | None = None


class RiskScoreComponentsSchema(BaseModel):
    ml_confidence: float
    asset_criticality: float
    attack_severity: float
    threat_intel: float | None = 0.0


class RiskScoreSchema(BaseModel):
    composite: float
    components: RiskScoreComponentsSchema | None = None
    weights: dict[str, float] | None = None


class ClassificationSchema(BaseModel):
    attack_class: str
    confidence: float
    probabilities: dict[str, float] | None = None


# --- Geolocation & Threat Intel Schemas ---


class GeoContextEntrySchema(BaseModel):
    """
    Geolocation data for a single IP.
    Caveat: City/region-level accuracy only; unreliable for VPN/proxy/CGNAT.
    """

    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: int | None = None
    asn_org: str | None = None
    is_private: bool = False
    is_synthetic: bool = False
    accuracy_caveat: str = "City-level accuracy; unreliable for VPN/proxy/CGNAT"


class GeoContextSchema(BaseModel):
    """Source and destination geolocation context."""

    source: GeoContextEntrySchema | None = None
    destination: GeoContextEntrySchema | None = None


class ThreatIntelEntrySchema(BaseModel):
    """
    Threat intelligence data for a source IP.
    Data source: AbuseIPDB free tier (1,000 checks/day).
    """

    abuse_confidence_score: int | None = 0
    total_reports: int | None = 0
    is_known_bad: bool = False
    last_reported_at: str | None = None
    provider: str | None = "none"


class ThreatIntelSchema(BaseModel):
    """Threat intel wrapper for source IP."""

    source_ip: ThreatIntelEntrySchema | None = None


# --- Alert Ingestion (from Detection Pipeline) ---


class AlertIngestSchema(BaseModel):
    alert_id: str | None = None
    timestamp: datetime | str | None = None
    source_ip: str
    dest_ip: str
    dest_port: int | None = None
    protocol: str | None = "TCP"
    flow_features: dict[str, Any] | None = None
    classification: ClassificationSchema
    shap_explanation: ShapExplanationSchema | None = None
    mitre_mapping: MitreMappingSchema | None = None
    risk_score: RiskScoreSchema | float
    geo_context: GeoContextSchema | None = None
    threat_intel: ThreatIntelSchema | None = None
    dataset_source: str | None = "CIC-IDS2017"
    domain: str | None = "network"


class AlertStatusUpdate(BaseModel):
    status: str = Field(
        ..., description="Status: new, investigating, resolved, dismissed, closed"
    )


class AlertShapFeatureResponse(BaseModel):
    id: str
    feature_name: str
    shap_value: float
    feature_value: float | None = None
    rank: int

    class Config:
        from_attributes = True


class AlertResponse(BaseModel):
    id: str
    detected_at: datetime
    source_ip: str
    dest_ip: str
    dest_port: int | None = None
    protocol: str | None = "TCP"
    flow_features: dict[str, Any] | None = None
    attack_class: str
    ml_confidence: float
    class_probabilities: dict[str, float] | None = None
    mitre_technique_id: str | None = None
    mitre_technique_name: str | None = None
    mitre_tactic: str | None = None
    mitre_severity: str | None = None
    mitre_description: str | None = None
    asset_criticality: float
    risk_score: float
    risk_score_components: dict[str, Any] | None = None
    # Geolocation fields
    geo_source_country: str | None = None
    geo_source_country_code: str | None = None
    geo_source_region: str | None = None
    geo_source_city: str | None = None
    geo_source_lat: float | None = None
    geo_source_lon: float | None = None
    geo_source_asn: int | None = None
    geo_source_asn_org: str | None = None
    geo_is_synthetic: bool | None = False
    # Threat intel fields
    threat_intel_score: float | None = None
    threat_intel_reports: int | None = None
    threat_intel_is_known_bad: bool | None = False
    threat_intel_provider: str | None = None
    # Status
    status: str
    ingested_at: datetime
    shap_features: list[AlertShapFeatureResponse] | None = []
    # Dataset & Domain
    dataset_source: str | None = "CIC-IDS2017"
    domain: str | None = "network"

    class Config:
        from_attributes = True


class AlertListResponse(BaseModel):
    alerts: list[AlertResponse]
    total: int
    page: int
    pages: int
    limit: int


class PlainLanguageExplanation(BaseModel):
    summary: str
    primary_contributors: list[str]
    mitre_context: str
    recommended_action: str


class AlertExplanationResponse(BaseModel):
    model_config = {"protected_namespaces": ()}
    alert_id: str
    attack_class: str
    ml_confidence: float
    base_value: float
    features: list[AlertShapFeatureResponse]
    plain_language: PlainLanguageExplanation
    dataset_source: str | None = "CIC-IDS2017"
    domain: str | None = "network"
    model_name: str | None = "XGBoost Classifier"


# --- Geolocation API Schemas ---


class GeoAlertMapEntry(BaseModel):
    """Single alert entry for the geo map visualization."""

    alert_id: str
    source_ip: str
    attack_class: str
    risk_score: float
    mitre_severity: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    asn_org: str | None = None
    threat_intel_score: float | None = None
    is_known_bad: bool = False
    is_synthetic: bool = False
    detected_at: datetime


class GeoAlertsMapResponse(BaseModel):
    """Response for the geo map alerts endpoint."""

    alerts: list[GeoAlertMapEntry]
    total: int
    caveat: str = (
        "IP geolocation is approximate (city/region-level). "
        "Locations are unreliable for VPN/proxy/CGNAT traffic. "
        "Lab dataset IPs use synthetic coordinates for demonstration."
    )


class CountrySummaryEntry(BaseModel):
    country: str
    country_code: str | None = None
    alert_count: int
    avg_risk_score: float
    known_bad_count: int


class CountrySummaryResponse(BaseModel):
    countries: list[CountrySummaryEntry]
    total_countries: int


class ThreatIntelSummaryEntry(BaseModel):
    source_ip: str
    abuse_confidence_score: float
    total_reports: int
    alert_count: int
    attack_classes: list[str]
    country: str | None = None


class ThreatIntelSummaryResponse(BaseModel):
    known_bad_ips: list[ThreatIntelSummaryEntry]
    total_known_bad: int
    total_alerts_from_known_bad: int
