"""
Alert service for processing, querying, and explaining intrusion detection alerts.
Handles geolocation context and threat intelligence data persistence.
"""

import uuid
from datetime import datetime

from app.models.alert import Alert, AlertShapFeature
from app.schemas.alert_schema import (
    AlertExplanationResponse,
    AlertIngestSchema,
    AlertListResponse,
    AlertResponse,
    AlertShapFeatureResponse,
    PlainLanguageExplanation,
)
from sqlalchemy import asc, desc
from sqlalchemy.orm import Session


class AlertService:
    @staticmethod
    def ingest_alert(db: Session, data: AlertIngestSchema) -> Alert:
        """
        Normalize and persist incoming alert JSON from detection pipeline.
        Carries SHAP explainability values, geolocation, and threat-intel
        directly into the database.
        """
        # Resolve risk score and components
        if isinstance(data.risk_score, (int, float)):
            composite_risk = float(data.risk_score)
            risk_components = {
                "ml_confidence": data.classification.confidence,
                "asset_criticality": 0.5,
                "attack_severity": 0.5,
                "threat_intel": 0.0,
            }
        else:
            composite_risk = data.risk_score.composite
            risk_components = (
                data.risk_score.components.model_dump()
                if data.risk_score.components
                else None
            )

        # Resolve timestamp
        detected_time = datetime.utcnow()
        if data.timestamp:
            if isinstance(data.timestamp, str):
                try:
                    detected_time = datetime.fromisoformat(
                        data.timestamp.replace("Z", "+00:00")
                    )
                except Exception:
                    detected_time = datetime.utcnow()
            elif isinstance(data.timestamp, datetime):
                detected_time = data.timestamp

        # Extract MITRE details
        mitre_id = data.mitre_mapping.technique_id if data.mitre_mapping else None
        mitre_name = data.mitre_mapping.technique_name if data.mitre_mapping else None
        mitre_tactic = data.mitre_mapping.tactic if data.mitre_mapping else None
        mitre_severity = data.mitre_mapping.severity if data.mitre_mapping else None
        mitre_desc = data.mitre_mapping.description if data.mitre_mapping else None

        # Extract geolocation context (source IP)
        geo_country = None
        geo_country_code = None
        geo_region = None
        geo_city = None
        geo_lat = None
        geo_lon = None
        geo_asn = None
        geo_asn_org = None
        geo_is_synthetic = False

        if data.geo_context and data.geo_context.source:
            src_geo = data.geo_context.source
            geo_country = src_geo.country
            geo_country_code = src_geo.country_code
            geo_region = src_geo.region
            geo_city = src_geo.city
            geo_lat = src_geo.latitude
            geo_lon = src_geo.longitude
            geo_asn = src_geo.asn
            geo_asn_org = src_geo.asn_org
            geo_is_synthetic = src_geo.is_synthetic

        # Extract threat intelligence
        ti_score = None
        ti_reports = None
        ti_is_known_bad = False
        ti_provider = None

        if data.threat_intel and data.threat_intel.source_ip:
            ti = data.threat_intel.source_ip
            ti_score = ti.abuse_confidence_score
            ti_reports = ti.total_reports
            ti_is_known_bad = ti.is_known_bad
            ti_provider = ti.provider

        alert_id = data.alert_id or str(uuid.uuid4())

        alert = Alert(
            id=alert_id,
            detected_at=detected_time,
            source_ip=data.source_ip,
            dest_ip=data.dest_ip,
            dest_port=data.dest_port,
            protocol=data.protocol or "TCP",
            flow_features=data.flow_features or {},
            attack_class=data.classification.attack_class,
            ml_confidence=data.classification.confidence,
            class_probabilities=data.classification.probabilities or {},
            mitre_technique_id=mitre_id,
            mitre_technique_name=mitre_name,
            mitre_tactic=mitre_tactic,
            mitre_severity=mitre_severity,
            mitre_description=mitre_desc,
            asset_criticality=risk_components.get("asset_criticality", 0.5)
            if risk_components
            else 0.5,
            risk_score=round(composite_risk, 4),
            risk_score_components=risk_components,
            # Geolocation
            geo_source_country=geo_country,
            geo_source_country_code=geo_country_code,
            geo_source_region=geo_region,
            geo_source_city=geo_city,
            geo_source_lat=geo_lat,
            geo_source_lon=geo_lon,
            geo_source_asn=geo_asn,
            geo_source_asn_org=geo_asn_org,
            geo_is_synthetic=geo_is_synthetic,
            # Threat Intel
            threat_intel_score=ti_score,
            threat_intel_reports=ti_reports,
            threat_intel_is_known_bad=ti_is_known_bad,
            threat_intel_provider=ti_provider,
            # Status
            status="new",
            ingested_at=datetime.utcnow(),
            # Dataset & Domain
            dataset_source=getattr(data, "dataset_source", None) or "CIC-IDS2017",
            domain=getattr(data, "domain", None) or "network",
        )

        db.add(alert)
        db.flush()

        # Save SHAP feature explanations
        if data.shap_explanation and data.shap_explanation.feature_contributions:
            for idx, contrib in enumerate(data.shap_explanation.feature_contributions):
                feat_obj = AlertShapFeature(
                    id=str(uuid.uuid4()),
                    alert_id=alert.id,
                    feature_name=contrib.feature,
                    shap_value=round(contrib.shap_value, 4),
                    feature_value=round(contrib.feature_value, 4)
                    if contrib.feature_value is not None
                    else None,
                    rank=contrib.rank or (idx + 1),
                )
                db.add(feat_obj)

        db.commit()
        db.refresh(alert)
        return alert

    @staticmethod
    def list_alerts(
        db: Session,
        status: str | None = None,
        attack_class: str | None = None,
        severity: str | None = None,
        source_ip: str | None = None,
        dest_ip: str | None = None,
        min_risk: float | None = None,
        search: str | None = None,
        dataset: str | None = None,
        domain: str | None = None,
        sort_by: str = "risk_score",
        order: str = "desc",
        page: int = 1,
        limit: int = 25,
    ) -> AlertListResponse:
        """
        Query alerts with rich filtering, search, sorting and pagination.
        """
        from sqlalchemy import or_

        query = db.query(Alert)

        if status:
            query = query.filter(Alert.status == status)
        if attack_class:
            query = query.filter(Alert.attack_class == attack_class)
        if severity:
            query = query.filter(Alert.mitre_severity == severity)
        if source_ip:
            query = query.filter(Alert.source_ip.ilike(f"%{source_ip}%"))
        if dest_ip:
            query = query.filter(Alert.dest_ip.ilike(f"%{dest_ip}%"))
        if min_risk is not None:
            query = query.filter(Alert.risk_score >= min_risk)
        if dataset:
            ds_list = [d.strip() for d in dataset.split(",") if d.strip()]
            if len(ds_list) == 1:
                query = query.filter(Alert.dataset_source.ilike(f"%{ds_list[0]}%"))
            elif ds_list:
                conditions = [Alert.dataset_source.ilike(f"%{d}%") for d in ds_list]
                query = query.filter(or_(*conditions))
        if domain:
            dom_list = [d.strip() for d in domain.split(",") if d.strip()]
            if len(dom_list) == 1:
                query = query.filter(Alert.domain.ilike(f"%{dom_list[0]}%"))
            elif dom_list:
                conditions = [Alert.domain.ilike(f"%{d}%") for d in dom_list]
                query = query.filter(or_(*conditions))
        if search:
            search_pattern = f"%{search}%"
            query = query.filter(
                (Alert.source_ip.ilike(search_pattern))
                | (Alert.dest_ip.ilike(search_pattern))
                | (Alert.attack_class.ilike(search_pattern))
                | (Alert.mitre_technique_id.ilike(search_pattern))
                | (Alert.mitre_technique_name.ilike(search_pattern))
                | (Alert.geo_source_country.ilike(search_pattern))
                | (Alert.dataset_source.ilike(search_pattern))
                | (Alert.domain.ilike(search_pattern))
            )

        total = query.count()

        # Sorting
        sort_column = getattr(Alert, sort_by, Alert.risk_score)
        if order.lower() == "asc":
            query = query.order_by(asc(sort_column))
        else:
            query = query.order_by(desc(sort_column))

        # Pagination
        offset = (page - 1) * limit
        alerts = query.offset(offset).limit(limit).all()

        pages = max(1, (total + limit - 1) // limit)

        # Convert to Pydantic responses
        alert_responses = [AlertResponse.model_validate(a) for a in alerts]

        return AlertListResponse(
            alerts=alert_responses, total=total, page=page, pages=pages, limit=limit
        )

    @staticmethod
    def get_alert_by_id(db: Session, alert_id: str) -> Alert | None:
        """Fetch alert with full relationships."""
        return db.query(Alert).filter(Alert.id == alert_id).first()

    @staticmethod
    def update_status(db: Session, alert_id: str, new_status: str) -> Alert | None:
        """Update triage status for an alert."""
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return None
        alert.status = new_status
        db.commit()
        db.refresh(alert)
        return alert

    @staticmethod
    def delete_alert(db: Session, alert_id: str) -> bool:
        """Delete an alert."""
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return False
        db.delete(alert)
        db.commit()
        return True

    @staticmethod
    def get_explanation(
        db: Session, alert_id: str
    ) -> AlertExplanationResponse | None:
        """
        Generate analyst-friendly explanation with SHAP waterfall values,
        top contributors, and plain language summary.
        """
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return None

        features = (
            db.query(AlertShapFeature)
            .filter(AlertShapFeature.alert_id == alert_id)
            .order_by(asc(AlertShapFeature.rank))
            .all()
        )

        # Sort positive and negative contributors
        top_pos = [f for f in features if f.shap_value > 0][:3]

        # Build plain language narrative
        pos_reasons = []
        for f in top_pos:
            val_str = f" ({f.feature_value:.2f})" if f.feature_value is not None else ""
            pos_reasons.append(
                f"{f.feature_name}{val_str} pushed the risk score by +{f.shap_value:.3f}"
            )

        confidence_pct = int(alert.ml_confidence * 100)

        # Add geo/threat-intel context to the summary
        geo_context_str = ""
        if alert.geo_source_country:
            geo_context_str = f" Source IP geolocated to {alert.geo_source_city or ''}, {alert.geo_source_country}"
            if alert.geo_source_asn_org:
                geo_context_str += f" (ASN: {alert.geo_source_asn_org})"
            geo_context_str += "."
            if alert.geo_is_synthetic:
                geo_context_str += " [Note: geolocation is synthetic — lab/private IP.]"

        threat_context_str = ""
        if alert.threat_intel_is_known_bad:
            threat_context_str = (
                f" ⚠️ Source IP flagged as KNOWN BAD by {alert.threat_intel_provider or 'threat-intel'} "
                f"(abuse score: {alert.threat_intel_score or 0:.0f}/100, "
                f"{alert.threat_intel_reports or 0} reports)."
            )
        elif alert.threat_intel_score and alert.threat_intel_score > 0:
            threat_context_str = (
                f" Source IP has {alert.threat_intel_reports or 0} abuse reports "
                f"(score: {alert.threat_intel_score:.0f}/100)."
            )

        summary = (
            f"Alert was classified as {alert.attack_class} with {confidence_pct}% model confidence. "
            f"Key driving indicators: {', '.join(pos_reasons) if pos_reasons else 'Baseline distribution match'}."
            f"{geo_context_str}{threat_context_str}"
        )

        mitre_context = (
            f"Correlated to MITRE ATT&CK {alert.mitre_technique_id or 'Unknown'} "
            f"({alert.mitre_technique_name or 'N/A'}) under tactic {alert.mitre_tactic or 'Unknown'}. "
            f"{alert.mitre_description or ''}"
        )

        # Action recommendation based on class
        recommended_actions = {
            "DDoS": "Review ingress bandwidth at perimeter firewall. Apply rate-limiting to destination port and inspect source subnet.",
            "DoS Hulk": "Inspect HTTP web server request volume. Validate keep-alive connections and apply mod_evasive or WAF rate limit.",
            "PortScan": "Cross-reference source IP against vulnerability scanner allowlist. If unapproved, block host at sensor.",
            "FTP-Patator": "Check authentication logs on FTP service. Enforce fail2ban and lock repeated failed logon attempts.",
            "SSH-Patator": "Verify SSH host key and failed auth attempts. Restrict SSH access to bastion IP or VPN.",
            "Web Attack": "Inspect URI query parameters and POST body for SQL injection or script tags. Verify WAF rules.",
            "Botnet": "Isolate infected internal host from VLAN. Check DNS queries for DGA or known C2 domains.",
            "Infiltration": "Immediately isolate target host. Collect RAM image and process execution logs for lateral movement analysis.",
            "Benign": "No immediate containment required. Monitor for unusual threshold spikes.",
        }
        rec_action = recommended_actions.get(
            alert.attack_class,
            "Inspect network flow telemetry, verify asset criticality, and triage according to standard SOC playbook.",
        )

        ds_name = alert.dataset_source or "CIC-IDS2017"
        dom_name = alert.domain or "network"
        model_arch_map = {
            "ciciot2023": "Random Forest (IoT Topology)",
            "edge_iiotset": "Random Forest (Edge-IIoT)",
            "nf_ton_iot_v3": "XGBoost (NetFlow v3)",
            "cic_ids2017": "XGBoost Classifier",
            "cic-ids2017": "XGBoost Classifier",
            "iomt_careflow": "LightGBM (Healthcare IoMT)",
            "iomt-careflow": "LightGBM (Healthcare IoMT)",
        }
        model_name = model_arch_map.get(
            ds_name.lower().replace("-", "_"), "XGBoost Classifier"
        )

        plain_lang = PlainLanguageExplanation(
            summary=f"[{ds_name} / {model_name}] {summary}",
            primary_contributors=[
                f"{f.feature_name} (+{f.shap_value:.3f})" for f in top_pos
            ],
            mitre_context=mitre_context,
            recommended_action=rec_action,
        )

        feat_responses = [AlertShapFeatureResponse.model_validate(f) for f in features]

        return AlertExplanationResponse(
            alert_id=alert.id,
            attack_class=alert.attack_class,
            ml_confidence=alert.ml_confidence,
            base_value=0.10,
            features=feat_responses,
            plain_language=plain_lang,
            dataset_source=ds_name,
            domain=dom_name,
            model_name=model_name,
        )
