import React, { useState, useEffect, useCallback } from "react";
import { api } from "../api/client";
import CommandDeckKpiStrip from "../components/CommandDeckKpiStrip";
import CommandDeckFilterBar from "../components/CommandDeckFilterBar";
import DatasetHealthCards from "../components/DatasetHealthCards";
import DomainBreakdownChart from "../components/DomainBreakdownChart";
import { DatasetBadge, DomainBadge } from "../utils/datasetConstants";
import { Shield, Activity, RefreshCw } from "lucide-react";

export default function Dashboard({
  onNavigateAlerts,
  onSelectAlert,
  onNavigateCases,
}) {
  const [summary, setSummary] = useState(null);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Multi-select filters for datasets and domains
  const [selectedDatasets, setSelectedDatasets] = useState([]);
  const [selectedDomains, setSelectedDomains] = useState([]);

  // Load summary and alerts
  const loadDashboardData = useCallback(async () => {
    try {
      setRefreshing(true);
      const queryParams = {
        limit: 8,
        sort_by: "risk_score",
        order: "desc",
      };
      if (selectedDatasets.length > 0) {
        queryParams.dataset = selectedDatasets.join(",");
      }
      if (selectedDomains.length > 0) {
        queryParams.domain = selectedDomains.join(",");
      }

      const [sumRes, alertsRes] = await Promise.all([
        api.getSummary(),
        api.getAlerts(queryParams),
      ]);
      setSummary(sumRes);
      setRecentAlerts(alertsRes.alerts || []);
    } catch (err) {
      console.error("Failed to load dashboard:", err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [selectedDatasets, selectedDomains]);

  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  // Toggle dataset multi-select
  const handleToggleDataset = (datasetId) => {
    setSelectedDatasets((prev) =>
      prev.includes(datasetId)
        ? prev.filter((d) => d !== datasetId)
        : [...prev, datasetId],
    );
  };

  // Toggle domain multi-select
  const handleToggleDomain = (domainId) => {
    setSelectedDomains((prev) =>
      prev.includes(domainId)
        ? prev.filter((d) => d !== domainId)
        : [...prev, domainId],
    );
  };

  // Clear all filters
  const handleClearFilters = () => {
    setSelectedDatasets([]);
    setSelectedDomains([]);
  };

  const getRiskBadge = (score) => {
    const pct = (score * 100).toFixed(0);
    if (score >= 0.75)
      return <span className="sec-badge sec-badge-crit">[P1 CRIT] {pct}%</span>;
    if (score >= 0.5)
      return <span className="sec-badge sec-badge-high">[P2 HIGH] {pct}%</span>;
    if (score >= 0.3)
      return <span className="sec-badge sec-badge-med">[P3 MED] {pct}%</span>;
    return <span className="sec-badge sec-badge-low">[P4 LOW] {pct}%</span>;
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
      {/* 1. Tactical Command Header */}
      <div className="command-strip">
        <div className="command-strip-left">
          <div className="command-deck-title">
            <span>PERIMETER THREAT TRIAGE & SURVEILLANCE</span>
            <span
              className="sec-badge sec-badge-neutral"
              style={{ letterSpacing: "0.06em" }}
            >
              CROSS-DOMAIN // SOC CORE
            </span>
          </div>

          <div className="command-status-pills">
            <span className="status-pip active">5 SENSORS STREAMING</span>
            <span className="status-pip active">XAI TREE-EXPLAINER ONLINE</span>
            <span className="status-pip active">
              UNIFIED MULTI-DATASET QUEUE
            </span>
          </div>
        </div>

        <div className="command-strip-actions">
          <button
            className="sec-btn sec-btn-ghost sec-btn-sm"
            onClick={loadDashboardData}
            disabled={refreshing}
            title="Refresh Ingested Telemetry"
          >
            <RefreshCw size={12} className={refreshing ? "spin" : ""} />
            <span>Sync</span>
          </button>
          <button
            className="sec-btn sec-btn-primary sec-btn-sm"
            onClick={onNavigateAlerts}
          >
            <span>Alert Queue</span>
            <span
              style={{
                opacity: 0.6,
                fontSize: "10px",
                fontFamily: "var(--font-mono)",
              }}
            >
              [Q]
            </span>
          </button>
          <button className="sec-btn sec-btn-sm" onClick={onNavigateCases}>
            <span>Active Cases</span>
            <span
              style={{
                opacity: 0.6,
                fontSize: "10px",
                fontFamily: "var(--font-mono)",
              }}
            >
              [C]
            </span>
          </button>
        </div>
      </div>

      {/* 2. Combined KPI Strip at the top (Required: total alerts today, high-severity count, average model confidence, number of active datasets) */}
      <CommandDeckKpiStrip
        kpi={summary?.kpi}
        totalAlerts={summary?.total_alerts}
        criticalCount={summary?.critical_alerts}
      />

      {/* 3. Multi-Select Dataset & Domain Scope Selector */}
      <CommandDeckFilterBar
        selectedDatasets={selectedDatasets}
        selectedDomains={selectedDomains}
        onToggleDataset={handleToggleDataset}
        onToggleDomain={handleToggleDomain}
        onClearFilters={handleClearFilters}
        datasetCounts={summary?.dataset_breakdown || {}}
        domainCounts={summary?.domain_breakdown || {}}
      />

      {/* 4. Per-Dataset Health Card Row (Required: model status, last-eval accuracy/F1, record count, last trained timestamp — scrollable) */}
      <DatasetHealthCards
        healthData={summary?.dataset_health || []}
        selectedDatasets={selectedDatasets}
        onToggleDataset={handleToggleDataset}
      />

      {/* 5. Main Tactical Grid: Live Unified Threat Stream (65%) + Domain Breakdown & MITRE (35%) */}
      <div className="tactical-split-66-34">
        {/* Left: Unified Live Threat Stream */}
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <Activity size={14} style={{ color: "var(--signal-crit)" }} />
              <span>Live Ingested Threat Triage Stream</span>
              {(selectedDatasets.length > 0 || selectedDomains.length > 0) && (
                <span
                  className="sec-badge sec-badge-mitre"
                  style={{ fontSize: "10px" }}
                >
                  FILTERED
                </span>
              )}
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span className="panel-badge">TOP RISK RANKED</span>
              <button
                className="sec-btn sec-btn-ghost sec-btn-sm"
                onClick={onNavigateAlerts}
              >
                Full Unified Queue ↗
              </button>
            </div>
          </div>

          <div className="panel-body-flush sec-table-container">
            <table className="sec-table">
              <thead>
                <tr>
                  <th style={{ width: "105px" }}>Priority</th>
                  <th>Dataset / Domain</th>
                  <th>Vector Class</th>
                  <th>Flow Coordinates (Src → Dst:Port)</th>
                  <th style={{ width: "85px" }}>ML Conf</th>
                  <th style={{ width: "110px" }}>MITRE Tag</th>
                  <th style={{ width: "75px", textAlign: "right" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {recentAlerts.length === 0 ? (
                  <tr>
                    <td
                      colSpan="7"
                      style={{
                        textAlign: "center",
                        padding: "28px",
                        color: "var(--text-muted)",
                      }}
                    >
                      No active threats match the current dataset/domain filter.
                    </td>
                  </tr>
                ) : (
                  recentAlerts.map((a) => (
                    <tr key={a.id} onClick={() => onSelectAlert(a.id)}>
                      <td>{getRiskBadge(a.risk_score)}</td>
                      <td>
                        <div
                          style={{
                            display: "flex",
                            flexDirection: "column",
                            gap: "2px",
                          }}
                        >
                          <DatasetBadge dataset={a.dataset_source} size="sm" />
                          <div style={{ marginTop: "1px" }}>
                            <DomainBadge domain={a.domain} size="sm" />
                          </div>
                        </div>
                      </td>
                      <td>
                        <strong
                          style={{ color: "#fff", letterSpacing: "-0.01em" }}
                        >
                          {a.attack_class}
                        </strong>
                      </td>
                      <td>
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "5px",
                          }}
                        >
                          <span className="mono-ip">{a.source_ip}</span>
                          <span style={{ color: "var(--text-muted)" }}>→</span>
                          <span
                            className="mono-ip"
                            style={{ color: "var(--text-secondary)" }}
                          >
                            {a.dest_ip}:{a.dest_port || "Any"}
                          </span>
                        </div>
                      </td>
                      <td>
                        <span
                          className="mono-time"
                          style={{ color: "var(--cyan-bright)" }}
                        >
                          {(a.ml_confidence * 100).toFixed(1)}%
                        </span>
                      </td>
                      <td>
                        {a.mitre_technique_id ? (
                          <span className="sec-badge sec-badge-mitre">
                            {a.mitre_technique_id}
                          </span>
                        ) : (
                          <span
                            style={{
                              color: "var(--text-dim)",
                              fontSize: "11px",
                            }}
                          >
                            —
                          </span>
                        )}
                      </td>
                      <td style={{ textAlign: "right" }}>
                        <button
                          className="sec-btn sec-btn-ghost sec-btn-sm"
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectAlert(a.id);
                          }}
                          style={{ padding: "2px 6px", fontSize: "10.5px" }}
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right: Domain Breakdown Chart + MITRE ATT&CK Matrix */}
        <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          {/* Domain Breakdown Chart (Required: donut/bar split by network, iot, iomt, iiot) */}
          <DomainBreakdownChart
            domainBreakdown={summary?.domain_breakdown || {}}
            selectedDomains={selectedDomains}
            onToggleDomain={handleToggleDomain}
          />

          {/* MITRE ATT&CK Framework Coverage */}
          <div className="panel">
            <div className="panel-header">
              <div className="panel-title">
                <Shield size={14} style={{ color: "var(--signal-mitre)" }} />
                <span>Cross-Dataset MITRE Coverage</span>
              </div>
              <span className="panel-badge">v15 ENTERPRISE</span>
            </div>

            <div
              className="panel-body"
              style={{ display: "flex", flexDirection: "column", gap: "8px" }}
            >
              {!summary?.top_mitre_techniques ||
              summary.top_mitre_techniques.length === 0 ? (
                <div
                  style={{
                    color: "var(--text-muted)",
                    fontSize: "12px",
                    padding: "12px",
                  }}
                >
                  No MITRE attributions detected in current window.
                </div>
              ) : (
                summary.top_mitre_techniques.slice(0, 4).map((t) => (
                  <div
                    key={`${t.technique_id}-${t.technique_name}`}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      padding: "7px 9px",
                      background: "var(--bg-inset)",
                      border: "1px solid var(--border-hairline)",
                      borderRadius: "var(--radius-xs)",
                    }}
                  >
                    <div>
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: "6px",
                          marginBottom: "2px",
                        }}
                      >
                        <span className="sec-badge sec-badge-mitre">
                          {t.technique_id}
                        </span>
                        <span
                          style={{
                            color: "#fff",
                            fontSize: "12px",
                            fontWeight: 600,
                          }}
                        >
                          {t.technique_name}
                        </span>
                      </div>
                      <div
                        style={{
                          fontSize: "10.5px",
                          color: "var(--text-muted)",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        TACTIC: {t.tactic.toUpperCase()}
                      </div>
                    </div>

                    <div style={{ textAlign: "right" }}>
                      <span
                        className="sec-badge sec-badge-crit"
                        style={{ fontSize: "9px" }}
                      >
                        {t.severity}
                      </span>
                      <div
                        className="mono-time"
                        style={{ color: "#fff", marginTop: "2px" }}
                      >
                        {t.count} hits
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
