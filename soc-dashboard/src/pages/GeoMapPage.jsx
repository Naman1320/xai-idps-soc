import React, { useState, useEffect, useMemo } from "react";
import {
  MapContainer,
  TileLayer,
  CircleMarker,
  Popup,
  useMap,
} from "react-leaflet";
import "leaflet/dist/leaflet.css";
import {
  Globe,
  AlertTriangle,
  Shield,
  Search,
  Map,
  BarChart2,
  ShieldAlert,
  ExternalLink,
} from "lucide-react";
import { api } from "../api/client";

// Severity → color mapping
const SEVERITY_COLORS = {
  critical: "#f43f5e",
  high: "#f59e0b",
  medium: "#eab308",
  low: "#10b981",
};

function getSeverityFromRisk(risk) {
  if (risk >= 0.85) return "critical";
  if (risk >= 0.65) return "high";
  if (risk >= 0.4) return "medium";
  return "low";
}

function getThreatBadge(alert) {
  if (alert.is_known_bad)
    return { label: "KNOWN BAD", color: "var(--signal-crit)", tag: "CRIT" };
  if (alert.threat_intel_score >= 50)
    return { label: "Suspicious", color: "var(--signal-high)", tag: "SUSP" };
  if (alert.threat_intel_score > 0)
    return { label: "Reports", color: "var(--cyan-bright)", tag: "INFO" };
  return { label: "Clean", color: "var(--signal-low)", tag: "CLEAN" };
}

// Component to fit map bounds to markers
function FitBounds({ positions }) {
  const map = useMap();
  useEffect(() => {
    if (positions.length > 0) {
      const bounds = positions.map((p) => [p[0], p[1]]);
      map.fitBounds(bounds, { padding: [30, 30], maxZoom: 5 });
    }
  }, [positions, map]);
  return null;
}

export default function GeoMapPage({ onSelectAlert }) {
  const [mapAlerts, setMapAlerts] = useState([]);
  const [countrySummary, setCountrySummary] = useState([]);
  const [threatSummary, setThreatSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState({
    attackClass: "",
    knownBadOnly: false,
    minRisk: 0,
  });
  const [activeView, setActiveView] = useState("map"); // 'map' | 'countries' | 'threats'
  const [caveat, setCaveat] = useState("");

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    setLoading(true);
    try {
      const [alertsRes, countriesRes, threatsRes] = await Promise.all([
        api.getGeoMapAlerts(200),
        api.getGeoCountries(),
        api.getThreatIntelSummary(),
      ]);
      setMapAlerts(alertsRes.alerts || []);
      setCountrySummary(countriesRes.countries || []);
      setThreatSummary(threatsRes);
      setCaveat(alertsRes.caveat || "");
    } catch (err) {
      console.error("Failed to load geo data:", err);
    } finally {
      setLoading(false);
    }
  }

  // Filtered alerts
  const filteredAlerts = useMemo(() => {
    return mapAlerts.filter((a) => {
      if (filter.attackClass && a.attack_class !== filter.attackClass)
        return false;
      if (filter.knownBadOnly && !a.is_known_bad) return false;
      if (a.risk_score < filter.minRisk) return false;
      return true;
    });
  }, [mapAlerts, filter]);

  const positions = useMemo(
    () =>
      filteredAlerts
        .filter((a) => a.latitude && a.longitude)
        .map((a) => [a.latitude, a.longitude]),
    [filteredAlerts],
  );

  const attackClasses = useMemo(
    () => [...new Set(mapAlerts.map((a) => a.attack_class))].sort(),
    [mapAlerts],
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
      {/* Header Command Strip */}
      <div className="command-strip">
        <div className="command-strip-left">
          <div className="command-deck-title">
            <Globe size={16} />
            <span>GEOLOCATION & PERIMETER THREAT INTELLIGENCE MAP</span>
            <span className="sec-badge sec-badge-neutral">
              {mapAlerts.length} MAPPED FLOWS
            </span>
          </div>

          <div className="command-status-pills">
            <span className="status-pip active">FEED: ABUSEIPDB v2</span>
            <span className="status-pip active">IP2LOCATION CITY</span>
          </div>
        </div>

        {/* View Toggle */}
        <div className="command-strip-actions">
          <button
            onClick={() => setActiveView("map")}
            className={`sec-btn sec-btn-sm ${activeView === "map" ? "sec-btn-primary" : "sec-btn-ghost"}`}
          >
            <Map size={12} />
            <span>Map Grid</span>
          </button>
          <button
            onClick={() => setActiveView("countries")}
            className={`sec-btn sec-btn-sm ${activeView === "countries" ? "sec-btn-primary" : "sec-btn-ghost"}`}
          >
            <BarChart2 size={12} />
            <span>Countries</span>
          </button>
          <button
            onClick={() => setActiveView("threats")}
            className={`sec-btn sec-btn-sm ${activeView === "threats" ? "sec-btn-primary" : "sec-btn-ghost"}`}
          >
            <ShieldAlert size={12} />
            <span>Known Threats</span>
          </button>
        </div>
      </div>

      {/* Accuracy Notice */}
      <div
        style={{
          background: "var(--bg-surface)",
          border: "1px solid var(--border-hairline)",
          borderRadius: "var(--radius-xs)",
          padding: "8px 12px",
          fontSize: "11px",
          color: "var(--text-muted)",
          display: "flex",
          alignItems: "center",
          gap: "8px",
          fontFamily: "var(--font-mono)",
        }}
      >
        <AlertTriangle
          size={13}
          style={{ color: "var(--signal-high)", flexShrink: 0 }}
        />
        <span>
          <strong style={{ color: "#fff" }}>PRECISION NOTICE:</strong>{" "}
          {caveat ||
            "IP geolocation is approximate (city/region-level). Unreliable for VPN/proxy/CGNAT traffic. Research test flows use synthetic coordinates."}
        </span>
      </div>

      {/* Filter Ribbon */}
      <div
        className="panel"
        style={{
          padding: "8px 12px",
          display: "flex",
          gap: "12px",
          alignItems: "center",
          flexWrap: "wrap",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
          <span
            style={{
              fontSize: "11px",
              color: "var(--text-muted)",
              textTransform: "uppercase",
              fontFamily: "var(--font-mono)",
            }}
          >
            Vector:
          </span>
          <select
            value={filter.attackClass}
            onChange={(e) =>
              setFilter((f) => ({ ...f, attackClass: e.target.value }))
            }
            className="sec-select"
            style={{ width: "160px", padding: "3px 8px", fontSize: "11px" }}
          >
            <option value="">All Vectors</option>
            {attackClasses.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </div>

        <label
          style={{
            display: "flex",
            alignItems: "center",
            gap: "6px",
            fontSize: "11.5px",
            color: "var(--text-secondary)",
            cursor: "pointer",
          }}
        >
          <input
            type="checkbox"
            checked={filter.knownBadOnly}
            onChange={(e) =>
              setFilter((f) => ({ ...f, knownBadOnly: e.target.checked }))
            }
          />
          <span>Known-Bad (AbuseIPDB) Only</span>
        </label>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "8px",
            fontSize: "11.5px",
            color: "var(--text-secondary)",
            marginLeft: "8px",
          }}
        >
          <span
            style={{
              fontSize: "11px",
              color: "var(--text-muted)",
              textTransform: "uppercase",
              fontFamily: "var(--font-mono)",
            }}
          >
            Min Risk:
          </span>
          <input
            type="range"
            min="0"
            max="100"
            step="5"
            value={filter.minRisk * 100}
            onChange={(e) =>
              setFilter((f) => ({
                ...f,
                minRisk: parseInt(e.target.value) / 100,
              }))
            }
            style={{ width: "80px", accentColor: "var(--cyan-bright)" }}
          />
          <span className="mono-time" style={{ color: "#fff" }}>
            {(filter.minRisk * 100).toFixed(0)}%
          </span>
        </div>
      </div>

      {loading ? (
        <div
          className="panel"
          style={{
            textAlign: "center",
            padding: "40px",
            color: "var(--text-muted)",
            fontSize: "12px",
            fontFamily: "var(--font-mono)",
          }}
        >
          RETRIEVING GEOLOCATION TELEMETRY...
        </div>
      ) : (
        <>
          {/* Map View */}
          {activeView === "map" && (
            <div className="panel">
              <div
                style={{
                  height: "520px",
                  width: "100%",
                  background: "#080a0d",
                }}
              >
                <MapContainer
                  center={[20, 0]}
                  zoom={2}
                  style={{
                    height: "100%",
                    width: "100%",
                    background: "#080a0d",
                  }}
                  scrollWheelZoom={true}
                >
                  <TileLayer
                    attribution='&copy; <a href="https://carto.com/">CARTO</a>'
                    url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
                  />
                  {positions.length > 0 && <FitBounds positions={positions} />}
                  {filteredAlerts
                    .filter((a) => a.latitude && a.longitude)
                    .map((alert) => {
                      const severity = getSeverityFromRisk(alert.risk_score);
                      const color = SEVERITY_COLORS[severity];
                      const threat = getThreatBadge(alert);
                      const radius = Math.max(
                        5,
                        Math.min(13, alert.risk_score * 14),
                      );

                      return (
                        <CircleMarker
                          key={alert.alert_id}
                          center={[alert.latitude, alert.longitude]}
                          radius={radius}
                          fillColor={color}
                          fillOpacity={0.75}
                          color={
                            alert.is_known_bad ? "var(--signal-crit)" : color
                          }
                          weight={alert.is_known_bad ? 2 : 1}
                          eventHandlers={{
                            click: () =>
                              onSelectAlert && onSelectAlert(alert.alert_id),
                          }}
                        >
                          <Popup>
                            <div
                              style={{
                                fontFamily: "Inter, sans-serif",
                                fontSize: "12px",
                                minWidth: "180px",
                                color: "#1a1d23",
                              }}
                            >
                              <div
                                style={{
                                  fontWeight: 700,
                                  marginBottom: "2px",
                                  color: "#0f172a",
                                }}
                              >
                                {alert.attack_class}
                              </div>
                              <div
                                style={{
                                  fontFamily: "monospace",
                                  color: "#475569",
                                  fontSize: "11px",
                                }}
                              >
                                {alert.source_ip}
                              </div>
                              <div
                                style={{
                                  marginTop: "4px",
                                  fontSize: "11px",
                                  color: "#334155",
                                }}
                              >
                                Origin: {alert.country || "Unknown"}{" "}
                                {alert.city ? `(${alert.city})` : ""}
                              </div>
                              <div
                                style={{
                                  marginTop: "2px",
                                  fontSize: "11px",
                                  fontWeight: 600,
                                }}
                              >
                                Risk: {(alert.risk_score * 100).toFixed(0)}% · [
                                {threat.label}]
                              </div>
                            </div>
                          </Popup>
                        </CircleMarker>
                      );
                    })}
                </MapContainer>
              </div>

              {/* Legend Ribbon */}
              <div
                style={{
                  display: "flex",
                  gap: "16px",
                  justifyContent: "center",
                  alignItems: "center",
                  padding: "8px 16px",
                  borderTop: "1px solid var(--border-hairline)",
                  fontSize: "11px",
                  fontFamily: "var(--font-mono)",
                  color: "var(--text-muted)",
                }}
              >
                <span>MARKER SCALE = RISK SCORE</span>
                <span
                  style={{ display: "flex", alignItems: "center", gap: "4px" }}
                >
                  <span
                    style={{
                      width: 7,
                      height: 7,
                      borderRadius: "50%",
                      background: SEVERITY_COLORS.critical,
                    }}
                  />{" "}
                  Critical
                </span>
                <span
                  style={{ display: "flex", alignItems: "center", gap: "4px" }}
                >
                  <span
                    style={{
                      width: 7,
                      height: 7,
                      borderRadius: "50%",
                      background: SEVERITY_COLORS.high,
                    }}
                  />{" "}
                  High
                </span>
                <span
                  style={{ display: "flex", alignItems: "center", gap: "4px" }}
                >
                  <span
                    style={{
                      width: 7,
                      height: 7,
                      borderRadius: "50%",
                      background: SEVERITY_COLORS.medium,
                    }}
                  />{" "}
                  Medium
                </span>
                <span
                  style={{ display: "flex", alignItems: "center", gap: "4px" }}
                >
                  <span
                    style={{
                      width: 7,
                      height: 7,
                      borderRadius: "50%",
                      background: SEVERITY_COLORS.low,
                    }}
                  />{" "}
                  Low
                </span>
                <span style={{ color: "var(--signal-crit)", fontWeight: 600 }}>
                  [CRIT] Known-Bad Threat Actor (AbuseIPDB)
                </span>
              </div>
            </div>
          )}

          {/* Country Distribution View */}
          {activeView === "countries" && (
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <Globe size={14} />
                  <span>Geographic Distribution (Country of Origin)</span>
                </div>
                <span className="panel-badge">
                  {countrySummary.length} ORIGIN REGIONS
                </span>
              </div>

              <div className="panel-body-flush sec-table-container">
                <table className="sec-table">
                  <thead>
                    <tr>
                      <th style={{ width: "70px" }}>ISO</th>
                      <th>Country Name</th>
                      <th style={{ width: "100px", textAlign: "right" }}>
                        Total Alerts
                      </th>
                      <th style={{ width: "100px", textAlign: "right" }}>
                        Mean Risk
                      </th>
                      <th style={{ width: "130px", textAlign: "right" }}>
                        Known-Bad Threats
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {countrySummary.map((c, i) => (
                      <tr key={i}>
                        <td>
                          <span className="sec-badge sec-badge-neutral">
                            {c.country_code || "XX"}
                          </span>
                        </td>
                        <td>
                          <strong style={{ color: "#fff" }}>
                            {c.country || "Unknown / Private Range"}
                          </strong>
                        </td>
                        <td style={{ textAlign: "right" }}>
                          <span className="mono-time" style={{ color: "#fff" }}>
                            {c.count}
                          </span>
                        </td>
                        <td style={{ textAlign: "right" }}>
                          <span
                            className="mono-time"
                            style={{
                              color:
                                SEVERITY_COLORS[
                                  getSeverityFromRisk(c.avg_risk_score)
                                ],
                              fontWeight: 600,
                            }}
                          >
                            {(c.avg_risk_score * 100).toFixed(0)}%
                          </span>
                        </td>
                        <td style={{ textAlign: "right" }}>
                          {c.known_bad_count > 0 ? (
                            <span className="sec-badge sec-badge-crit">
                              {c.known_bad_count} KNOWN BAD
                            </span>
                          ) : (
                            <span
                              className="mono-time"
                              style={{ color: "var(--text-muted)" }}
                            >
                              0
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Known Threats Summary View */}
          {activeView === "threats" && threatSummary && (
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <ShieldAlert size={14} />
                  <span>
                    Correlated Malicious Ingress Hosts (AbuseIPDB Threat
                    Intelligence)
                  </span>
                </div>
                <span className="panel-badge">
                  {threatSummary.total_known_bad} CONFIRMED ACTORS
                </span>
              </div>

              <div className="panel-body-flush sec-table-container">
                <table className="sec-table">
                  <thead>
                    <tr>
                      <th>Source Host Address</th>
                      <th style={{ width: "130px" }}>Confidence Score</th>
                      <th style={{ width: "90px", textAlign: "right" }}>
                        Reports
                      </th>
                      <th style={{ width: "90px", textAlign: "right" }}>
                        Ingested Alerts
                      </th>
                      <th>Attack Vectors</th>
                      <th>Origin</th>
                    </tr>
                  </thead>
                  <tbody>
                    {threatSummary.known_bad_ips.map((ip, i) => (
                      <tr key={i}>
                        <td>
                          <span
                            className="mono-ip"
                            style={{
                              color: "var(--signal-crit)",
                              fontWeight: 600,
                            }}
                          >
                            {ip.source_ip}
                          </span>
                        </td>
                        <td>
                          <div
                            style={{
                              display: "flex",
                              alignItems: "center",
                              gap: "6px",
                            }}
                          >
                            <div
                              style={{
                                width: "50px",
                                height: "4px",
                                borderRadius: "1px",
                                background: "var(--bg-inset)",
                              }}
                            >
                              <div
                                style={{
                                  width: `${ip.abuse_confidence_score}%`,
                                  height: "100%",
                                  background:
                                    ip.abuse_confidence_score >= 80
                                      ? "var(--signal-crit)"
                                      : "var(--signal-high)",
                                }}
                              />
                            </div>
                            <span
                              className="mono-time"
                              style={{ color: "#fff" }}
                            >
                              {ip.abuse_confidence_score}%
                            </span>
                          </div>
                        </td>
                        <td style={{ textAlign: "right" }}>
                          <span className="mono-time" style={{ color: "#fff" }}>
                            {ip.total_reports}
                          </span>
                        </td>
                        <td style={{ textAlign: "right" }}>
                          <span
                            className="mono-time"
                            style={{ color: "var(--cyan-bright)" }}
                          >
                            {ip.alert_count}
                          </span>
                        </td>
                        <td>
                          <div
                            style={{
                              display: "flex",
                              gap: "4px",
                              flexWrap: "wrap",
                            }}
                          >
                            {ip.attack_classes.map((cls) => (
                              <span
                                key={cls}
                                className="sec-badge sec-badge-mitre"
                                style={{ fontSize: "9.5px" }}
                              >
                                {cls}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td
                          style={{
                            color: "var(--text-secondary)",
                            fontSize: "11.5px",
                          }}
                        >
                          {ip.country || "Unknown"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
