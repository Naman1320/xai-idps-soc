import React from "react";
import { getDatasetMeta, getDomainMeta } from "../utils/datasetConstants";
import { Activity, CheckCircle2, ChevronRight, Cpu } from "lucide-react";

export default function DatasetHealthCards({
  healthData = [],
  selectedDatasets = [],
  onToggleDataset,
}) {
  if (!healthData || healthData.length === 0) {
    return null;
  }

  return (
    <div className="health-cards-section">
      <div className="health-cards-header">
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <Cpu size={14} style={{ color: "var(--cyan-bright)" }} />
          <span
            style={{
              fontSize: "12px",
              fontWeight: 700,
              letterSpacing: "0.04em",
              textTransform: "uppercase",
              color: "#fff",
            }}
          >
            Multi-Dataset Model Health & Sensor Telemetry
          </span>
          <span
            className="sec-badge sec-badge-neutral"
            style={{ fontSize: "10px" }}
          >
            {healthData.length} ACTIVE PIPELINES
          </span>
        </div>
        <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>
          Scroll horizontal ↔ Click card to toggle filter
        </span>
      </div>

      <div className="health-cards-scroll-container">
        {healthData.map((item) => {
          const meta = getDatasetMeta(item.dataset);
          const domainMeta = getDomainMeta(item.domain || meta.domain);
          const isSelected = selectedDatasets.includes(item.dataset);
          const DomainIcon = domainMeta.icon;

          return (
            <div
              key={item.dataset}
              className={`health-card ${isSelected ? "selected" : ""}`}
              onClick={() => onToggleDataset && onToggleDataset(item.dataset)}
              style={{
                borderColor: isSelected ? meta.color : undefined,
                boxShadow: isSelected
                  ? `0 0 12px ${meta.color}33, inset 0 0 8px ${meta.color}15`
                  : undefined,
              }}
            >
              {/* Card Top: Dataset Title & Domain Badge */}
              <div className="health-card-top">
                <div
                  style={{ display: "flex", alignItems: "center", gap: "6px" }}
                >
                  <span
                    style={{
                      width: "7px",
                      height: "7px",
                      borderRadius: "50%",
                      backgroundColor: meta.color,
                      boxShadow: `0 0 6px ${meta.color}`,
                    }}
                  />
                  <strong
                    style={{
                      color: "#fff",
                      fontSize: "13px",
                      letterSpacing: "-0.01em",
                    }}
                  >
                    {item.display_name || meta.displayName}
                  </strong>
                </div>

                <span
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: "3px",
                    padding: "1px 5px",
                    borderRadius: "2px",
                    fontSize: "9.5px",
                    fontWeight: 700,
                    fontFamily: "var(--font-mono)",
                    color: domainMeta.color,
                    backgroundColor: domainMeta.bg,
                    border: `1px solid ${domainMeta.border}`,
                    textTransform: "uppercase",
                  }}
                >
                  <DomainIcon size={9} />
                  <span>{domainMeta.tag}</span>
                </span>
              </div>

              {/* Model Status Indicator */}
              <div className="health-card-status-row">
                <div
                  style={{ display: "flex", alignItems: "center", gap: "5px" }}
                >
                  <span className="pulse-dot green" />
                  <span
                    style={{
                      fontSize: "11px",
                      color: "var(--signal-low)",
                      fontWeight: 600,
                      fontFamily: "var(--font-mono)",
                    }}
                  >
                    {item.status || "OPERATIONAL"}
                  </span>
                </div>
                <span
                  style={{
                    fontSize: "11px",
                    color: "var(--text-secondary)",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  {item.model || meta.defaultModel}
                </span>
              </div>

              {/* Metrics Grid */}
              <div className="health-card-metrics-grid">
                <div className="health-metric-box">
                  <span className="metric-label">Accuracy</span>
                  <span
                    className="metric-value"
                    style={{ color: "var(--cyan-bright)" }}
                  >
                    {item.accuracy
                      ? `${(item.accuracy * 100).toFixed(1)}%`
                      : `${(meta.defaultAccuracy * 100).toFixed(1)}%`}
                  </span>
                </div>

                <div className="metric-divider" />

                <div className="health-metric-box">
                  <span className="metric-label">Eval F1</span>
                  <span className="metric-value" style={{ color: "#60a5fa" }}>
                    {item.f1_score
                      ? item.f1_score.toFixed(3)
                      : meta.defaultF1.toFixed(3)}
                  </span>
                </div>

                <div className="metric-divider" />

                <div className="health-metric-box">
                  <span className="metric-label">Flows</span>
                  <span className="metric-value" style={{ color: "#fff" }}>
                    {item.record_count
                      ? Number(item.record_count).toLocaleString()
                      : "—"}
                  </span>
                </div>
              </div>

              {/* Card Footer: Last Trained Timestamp */}
              <div className="health-card-footer">
                <span style={{ color: "var(--text-muted)" }}>Trained:</span>
                <span
                  className="mono-time"
                  style={{ color: "var(--text-secondary)" }}
                >
                  {item.last_trained || "2026-09-28 23:45"}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
