"""
Geolocation & Threat Intelligence API endpoints.
Provides alert map data, country summaries, and threat-intel summaries
for the SOC dashboard Geo Map page.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from app.database import get_db
from app.models.alert import Alert
from app.schemas.alert_schema import (
    GeoAlertMapEntry,
    GeoAlertsMapResponse,
    CountrySummaryEntry,
    CountrySummaryResponse,
    ThreatIntelSummaryEntry,
    ThreatIntelSummaryResponse,
)

router = APIRouter(prefix="/geo", tags=["Geolocation & Threat Intel"])

GEO_CAVEAT = (
    "IP geolocation is approximate (city/region-level at best, ~55-80% city accuracy). "
    "Locations are unreliable for VPN/proxy/CGNAT traffic. "
    "Lab dataset IPs (CSE-CIC-IDS2018) use synthetic coordinates for demonstration. "
    "Geographic origin alone does NOT indicate maliciousness."
)


@router.get("/alerts-map", response_model=GeoAlertsMapResponse)
def get_alerts_map(
    limit: int = Query(500, ge=1, le=5000, description="Max alerts to return"),
    min_risk: Optional[float] = Query(None, ge=0.0, le=1.0),
    attack_class: Optional[str] = Query(None),
    country: Optional[str] = Query(None),
    known_bad_only: bool = Query(False, description="Only show known-bad IPs"),
    db: Session = Depends(get_db),
):
    """
    Get alerts with geolocation coordinates for map visualization.
    Only returns alerts that have lat/lon data.
    """
    query = db.query(Alert).filter(
        Alert.geo_source_lat.isnot(None),
        Alert.geo_source_lon.isnot(None),
    )

    if min_risk is not None:
        query = query.filter(Alert.risk_score >= min_risk)
    if attack_class:
        query = query.filter(Alert.attack_class == attack_class)
    if country:
        query = query.filter(Alert.geo_source_country.ilike(f"%{country}%"))
    if known_bad_only:
        query = query.filter(Alert.threat_intel_is_known_bad == True)

    alerts = query.order_by(desc(Alert.risk_score)).limit(limit).all()

    entries = []
    for a in alerts:
        entries.append(GeoAlertMapEntry(
            alert_id=a.id,
            source_ip=a.source_ip,
            attack_class=a.attack_class,
            risk_score=a.risk_score,
            mitre_severity=a.mitre_severity,
            latitude=a.geo_source_lat,
            longitude=a.geo_source_lon,
            country=a.geo_source_country,
            country_code=a.geo_source_country_code,
            city=a.geo_source_city,
            asn_org=a.geo_source_asn_org,
            threat_intel_score=a.threat_intel_score,
            is_known_bad=a.threat_intel_is_known_bad or False,
            is_synthetic=a.geo_is_synthetic or False,
            detected_at=a.detected_at,
        ))

    return GeoAlertsMapResponse(
        alerts=entries,
        total=len(entries),
        caveat=GEO_CAVEAT,
    )


@router.get("/country-summary", response_model=CountrySummaryResponse)
def get_country_summary(db: Session = Depends(get_db)):
    """
    Aggregate alert counts and average risk scores by country.
    """
    results = (
        db.query(
            Alert.geo_source_country,
            Alert.geo_source_country_code,
            func.count(Alert.id).label("alert_count"),
            func.avg(Alert.risk_score).label("avg_risk_score"),
        )
        .filter(Alert.geo_source_country.isnot(None))
        .group_by(Alert.geo_source_country, Alert.geo_source_country_code)
        .order_by(desc("alert_count"))
        .all()
    )

    countries = []
    for row in results:
        # Count known-bad IPs per country separately for SQLite compatibility
        known_bad = (
            db.query(func.count(Alert.id))
            .filter(
                Alert.geo_source_country == row[0],
                Alert.threat_intel_is_known_bad == True,
            )
            .scalar() or 0
        )
        countries.append(CountrySummaryEntry(
            country=row[0] or "Unknown",
            country_code=row[1],
            alert_count=row[2],
            avg_risk_score=round(row[3] or 0, 4),
            known_bad_count=known_bad,
        ))

    return CountrySummaryResponse(
        countries=countries,
        total_countries=len(countries),
    )


@router.get("/threat-intel-summary", response_model=ThreatIntelSummaryResponse)
def get_threat_intel_summary(
    min_score: int = Query(50, ge=0, le=100, description="Min abuse confidence score"),
    db: Session = Depends(get_db),
):
    """
    Summary of known-bad source IPs and their threat-intel scores.
    """
    # Get distinct source IPs with high abuse scores
    bad_ips_query = (
        db.query(
            Alert.source_ip,
            func.max(Alert.threat_intel_score).label("max_score"),
            func.max(Alert.threat_intel_reports).label("max_reports"),
            func.count(Alert.id).label("alert_count"),
            Alert.geo_source_country,
        )
        .filter(
            Alert.threat_intel_is_known_bad == True,
            Alert.threat_intel_score >= min_score,
        )
        .group_by(Alert.source_ip, Alert.geo_source_country)
        .order_by(desc("max_score"))
        .limit(50)
        .all()
    )

    entries = []
    total_alerts = 0
    for row in bad_ips_query:
        # Get attack classes for this IP
        attack_classes = (
            db.query(Alert.attack_class)
            .filter(Alert.source_ip == row[0])
            .distinct()
            .all()
        )
        classes = [ac[0] for ac in attack_classes]

        alert_count = row[3]
        total_alerts += alert_count

        entries.append(ThreatIntelSummaryEntry(
            source_ip=row[0],
            abuse_confidence_score=row[1] or 0,
            total_reports=row[2] or 0,
            alert_count=alert_count,
            attack_classes=classes,
            country=row[4],
        ))

    return ThreatIntelSummaryResponse(
        known_bad_ips=entries,
        total_known_bad=len(entries),
        total_alerts_from_known_bad=total_alerts,
    )
