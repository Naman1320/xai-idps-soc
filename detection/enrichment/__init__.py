"""
Alert Enrichment modules.

- MitreMapper: Attack class → ATT&CK technique lookup
- AssetContext: IP → asset criticality lookup
- RiskScorer: Composite risk score computation
- GeoEnricher: IP → geolocation (country/region/city/ASN) via MaxMind GeoLite2
- ThreatIntelEnricher: IP → threat reputation via AbuseIPDB
"""
