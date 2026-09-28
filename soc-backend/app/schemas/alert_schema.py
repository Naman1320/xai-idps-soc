"""
Pydantic schemas for alert ingestion, listing, detail, explanations,
geolocation context, and threat intelligence data.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field


class ShapFeatureContribution(BaseModel):
    feature: str
    shap_value: float
    feature_value: Optional[float] = None
    rank: Optional[int] = None


class ShapExplanationSchema(BaseModel):
    base_value: Optional[float] = 0.0
    feature_contributions: List[ShapFeatureContribution] = []


class MitreMappingSchema(BaseModel):
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    tactic: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None


class RiskScoreComponentsSchema(BaseModel):
    ml_confidence: float
    asset_criticality: float
    attack_severity: float
    threat_intel: Optional[float] = 0.0


class RiskScoreSchema(BaseModel):
    composite: float
    components: Optional[RiskScoreComponentsSchema] = None
    weights: Optional[Dict[str, float]] = None


class ClassificationSchema(BaseModel):
    attack_class: str
    confidence: float
    probabilities: Optional[Dict[str, float]] = None


# --- Geolocation & Threat Intel Schemas ---

class GeoContextEntrySchema(BaseModel):
    """
    Geolocation data for a single IP.
    Caveat: City/region-level accuracy only; unreliable for VPN/proxy/CGNAT.
    """
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    is_private: bool = False
    is_synthetic: bool = False
    accuracy_caveat: str = "City-level accuracy; unreliable for VPN/proxy/CGNAT"


class GeoContextSchema(BaseModel):
    """Source and destination geolocation context."""
    source: Optional[GeoContextEntrySchema] = None
    destination: Optional[GeoContextEntrySchema] = None


class ThreatIntelEntrySchema(BaseModel):
    """
    Threat intelligence data for a source IP.
    Data source: AbuseIPDB free tier (1,000 checks/day).
    """
    abuse_confidence_score: Optional[int] = 0
    total_reports: Optional[int] = 0
    is_known_bad: bool = False
    last_reported_at: Optional[str] = None
    provider: Optional[str] = "none"


class ThreatIntelSchema(BaseModel):
    """Threat intel wrapper for source IP."""
    source_ip: Optional[ThreatIntelEntrySchema] = None


# --- Alert Ingestion (from Detection Pipeline) ---

class AlertIngestSchema(BaseModel):
    alert_id: Optional[str] = None
    timestamp: Optional[Union[datetime, str]] = None
    source_ip: str
    dest_ip: str
    dest_port: Optional[int] = None
    protocol: Optional[str] = "TCP"
    flow_features: Optional[Dict[str, Any]] = None
    classification: ClassificationSchema
    shap_explanation: Optional[ShapExplanationSchema] = None
    mitre_mapping: Optional[MitreMappingSchema] = None
    risk_score: Union[RiskScoreSchema, float]
    geo_context: Optional[GeoContextSchema] = None
    threat_intel: Optional[ThreatIntelSchema] = None


class AlertStatusUpdate(BaseModel):
    status: str = Field(..., description="Status: new, investigating, resolved, dismissed, closed")


class AlertShapFeatureResponse(BaseModel):
    id: str
    feature_name: str
    shap_value: float
    feature_value: Optional[float] = None
    rank: int

    class Config:
        from_attributes = True


class AlertResponse(BaseModel):
    id: str
    detected_at: datetime
    source_ip: str
    dest_ip: str
    dest_port: Optional[int] = None
    protocol: Optional[str] = "TCP"
    flow_features: Optional[Dict[str, Any]] = None
    attack_class: str
    ml_confidence: float
    class_probabilities: Optional[Dict[str, float]] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_severity: Optional[str] = None
    mitre_description: Optional[str] = None
    asset_criticality: float
    risk_score: float
    risk_score_components: Optional[Dict[str, Any]] = None
    # Geolocation fields
    geo_source_country: Optional[str] = None
    geo_source_country_code: Optional[str] = None
    geo_source_region: Optional[str] = None
    geo_source_city: Optional[str] = None
    geo_source_lat: Optional[float] = None
    geo_source_lon: Optional[float] = None
    geo_source_asn: Optional[int] = None
    geo_source_asn_org: Optional[str] = None
    geo_is_synthetic: bool = False
    # Threat intel fields
    threat_intel_score: Optional[float] = None
    threat_intel_reports: Optional[int] = None
    threat_intel_is_known_bad: bool = False
    threat_intel_provider: Optional[str] = None
    # Status
    status: str
    ingested_at: datetime
    shap_features: Optional[List[AlertShapFeatureResponse]] = []

    class Config:
        from_attributes = True


class AlertListResponse(BaseModel):
    alerts: List[AlertResponse]
    total: int
    page: int
    pages: int
    limit: int


class PlainLanguageExplanation(BaseModel):
    summary: str
    primary_contributors: List[str]
    mitre_context: str
    recommended_action: str


class AlertExplanationResponse(BaseModel):
    alert_id: str
    attack_class: str
    ml_confidence: float
    base_value: float
    features: List[AlertShapFeatureResponse]
    plain_language: PlainLanguageExplanation


# --- Geolocation API Schemas ---

class GeoAlertMapEntry(BaseModel):
    """Single alert entry for the geo map visualization."""
    alert_id: str
    source_ip: str
    attack_class: str
    risk_score: float
    mitre_severity: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    asn_org: Optional[str] = None
    threat_intel_score: Optional[float] = None
    is_known_bad: bool = False
    is_synthetic: bool = False
    detected_at: datetime


class GeoAlertsMapResponse(BaseModel):
    """Response for the geo map alerts endpoint."""
    alerts: List[GeoAlertMapEntry]
    total: int
    caveat: str = (
        "IP geolocation is approximate (city/region-level). "
        "Locations are unreliable for VPN/proxy/CGNAT traffic. "
        "Lab dataset IPs use synthetic coordinates for demonstration."
    )


class CountrySummaryEntry(BaseModel):
    country: str
    country_code: Optional[str] = None
    alert_count: int
    avg_risk_score: float
    known_bad_count: int


class CountrySummaryResponse(BaseModel):
    countries: List[CountrySummaryEntry]
    total_countries: int


class ThreatIntelSummaryEntry(BaseModel):
    source_ip: str
    abuse_confidence_score: float
    total_reports: int
    alert_count: int
    attack_classes: List[str]
    country: Optional[str] = None


class ThreatIntelSummaryResponse(BaseModel):
    known_bad_ips: List[ThreatIntelSummaryEntry]
    total_known_bad: int
    total_alerts_from_known_bad: int
