import React from "react";
import { ShieldAlert, AlertTriangle, Target, Layers } from "lucide-react";

export default function CommandDeckKpiStrip({
  kpi,
  totalAlerts = 0,
  criticalCount = 0,
}) {
  const alertsToday = kpi?.total_alerts_today ?? totalAlerts ?? 0;
  const highSev = kpi?.high_severity_count ?? criticalCount ?? 0;
  const avgConf =
    kpi?.average_confidence !== undefined
      ? (kpi.average_confidence * 100).toFixed(1)
      : "93.9";
  const activeDatasets = kpi?.active_datasets_count ?? 5;

  return (
    <div className="telemetry-ribbon kpi-deck-ribbon">
      {/* KPI 1: Total Alerts Today */}
      <div className="telemetry-cell kpi-cell">
        <div className="telemetry-label">
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <ShieldAlert size={13} style={{ color: "var(--cyan-bright)" }} />
            <span>Total Alerts Today</span>
          </div>
          <span
            className="telemetry-badge"
            style={{
              color: "var(--cyan-bright)",
              background: "var(--cyan-subtle)",
            }}
          >
            INGESTED
          </span>
        </div>
        <div className="telemetry-value-row">
          <span className="telemetry-value" style={{ color: "#fff" }}>
            {Number(alertsToday).toLocaleString()}
          </span>
          <span className="telemetry-unit">events</span>
        </div>
        <div className="telemetry-subtext">
          <span>Across all active sensor pipelines</span>
        </div>
      </div>

      {/* KPI 2: High-Severity Count */}
      <div className="telemetry-cell kpi-cell">
        <div className="telemetry-label">
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <AlertTriangle size={13} style={{ color: "var(--signal-crit)" }} />
            <span>High / Critical Severity</span>
          </div>
          <span
            className="telemetry-badge"
            style={{
              color: "var(--signal-crit)",
              background: "var(--signal-crit-bg)",
            }}
          >
            P1 / P2 ALARM
          </span>
        </div>
        <div className="telemetry-value-row">
          <span
            className="telemetry-value"
            style={{ color: "var(--signal-crit)" }}
          >
            {Number(highSev).toLocaleString()}
          </span>
          <span className="telemetry-unit">critical</span>
        </div>
        <div className="telemetry-subtext">
          <span>Composite risk score ≥ 0.70</span>
        </div>
      </div>

      {/* KPI 3: Average Model Confidence */}
      <div className="telemetry-cell kpi-cell">
        <div className="telemetry-label">
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <Target size={13} style={{ color: "var(--signal-low)" }} />
            <span>Average Model Confidence</span>
          </div>
          <span
            className="telemetry-badge"
            style={{
              color: "var(--signal-low)",
              background: "var(--signal-low-bg)",
            }}
          >
            CALIBRATED
          </span>
        </div>
        <div className="telemetry-value-row">
          <span
            className="telemetry-value"
            style={{ color: "var(--signal-low)" }}
          >
            {avgConf}%
          </span>
          <span className="telemetry-unit">precision</span>
        </div>
        <div className="telemetry-subtext">
          <span>Multi-model tree ensemble mean</span>
        </div>
      </div>

      {/* KPI 4: Number of Active Datasets */}
      <div className="telemetry-cell kpi-cell">
        <div className="telemetry-label">
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <Layers size={13} style={{ color: "var(--signal-mitre)" }} />
            <span>Active Datasets Monitored</span>
          </div>
          <span
            className="telemetry-badge"
            style={{
              color: "var(--signal-mitre)",
              background: "var(--signal-mitre-bg)",
            }}
          >
            MULTI-SOURCE
          </span>
        </div>
        <div className="telemetry-value-row">
          <span
            className="telemetry-value"
            style={{ color: "var(--signal-mitre)" }}
          >
            {activeDatasets}
          </span>
          <span className="telemetry-unit">streams</span>
        </div>
        <div className="telemetry-subtext">
          <span>Network · IoT · IIoT · IoMT domains</span>
        </div>
      </div>
    </div>
  );
}
