import React from "react";

/**
 * Visual breakdown of the transparent composite risk score.
 * Formula: risk_score = w1 * ml_confidence + w2 * asset_criticality + w3 * attack_severity
 */
export default function RiskScoreBar({
  score,
  components,
  weights = { w1: 0.5, w2: 0.3, w3: 0.2 },
}) {
  const comp = components || {
    ml_confidence: 0.9,
    asset_criticality: 0.8,
    attack_severity: 0.85,
  };

  const w1 = weights.w1 || 0.5;
  const w2 = weights.w2 || 0.3;
  const w3 = weights.w3 || 0.2;

  const part1 = w1 * comp.ml_confidence;
  const part2 = w2 * comp.asset_criticality;
  const part3 = w3 * comp.attack_severity;

  const getScoreColor = (s) => {
    if (s >= 0.75) return "#f43f5e";
    if (s >= 0.5) return "#f97316";
    if (s >= 0.3) return "#eab308";
    return "#10b981";
  };

  const color = getScoreColor(score);

  return (
    <div className="card" style={{ padding: "16px" }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "10px",
        }}
      >
        <div>
          <span
            style={{
              fontSize: "0.75rem",
              textTransform: "uppercase",
              color: "var(--text-muted)",
              fontWeight: 600,
            }}
          >
            Composite Risk Score
          </span>
          <div style={{ display: "flex", alignItems: "baseline", gap: "8px" }}>
            <span
              className="mono"
              style={{ fontSize: "1.8rem", fontWeight: 800, color }}
            >
              {(score * 100).toFixed(1)}
            </span>
            <span style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
              / 100
            </span>
          </div>
        </div>

        <div style={{ textAlign: "right" }}>
          <span
            className="badge"
            style={{
              backgroundColor: `${color}20`,
              color,
              border: `1px solid ${color}60`,
              fontWeight: 700,
            }}
          >
            {score >= 0.75
              ? "CRITICAL RISK"
              : score >= 0.5
                ? "HIGH RISK"
                : score >= 0.3
                  ? "MEDIUM"
                  : "LOW"}
          </span>
        </div>
      </div>

      {/* Multi-segment stacked bar */}
      <div
        style={{
          display: "flex",
          height: "10px",
          borderRadius: "5px",
          overflow: "hidden",
          backgroundColor: "rgba(255, 255, 255, 0.05)",
          marginBottom: "12px",
        }}
      >
        <div
          title={`ML Confidence Part: ${(part1 * 100).toFixed(1)}%`}
          style={{
            width: `${part1 * 100}%`,
            backgroundColor: "#3b82f6",
            transition: "width 0.4s ease",
          }}
        />
        <div
          title={`Asset Criticality Part: ${(part2 * 100).toFixed(1)}%`}
          style={{
            width: `${part2 * 100}%`,
            backgroundColor: "#f59e0b",
            transition: "width 0.4s ease",
          }}
        />
        <div
          title={`ATT&CK Severity Part: ${(part3 * 100).toFixed(1)}%`}
          style={{
            width: `${part3 * 100}%`,
            backgroundColor: "#8b5cf6",
            transition: "width 0.4s ease",
          }}
        />
      </div>

      {/* Breakdown Math Details */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(3, 1fr)",
          gap: "8px",
          fontSize: "0.74rem",
        }}
      >
        <div
          style={{
            background: "rgba(59, 130, 246, 0.08)",
            padding: "6px 8px",
            borderRadius: "4px",
            border: "1px solid rgba(59, 130, 246, 0.2)",
          }}
        >
          <div style={{ color: "#60a5fa", fontWeight: 600 }}>
            ML Conf ({w1 * 100}%)
          </div>
          <div className="mono" style={{ color: "#fff" }}>
            {(comp.ml_confidence * 100).toFixed(1)}% (+
            {(part1 * 100).toFixed(1)})
          </div>
        </div>

        <div
          style={{
            background: "rgba(245, 158, 11, 0.08)",
            padding: "6px 8px",
            borderRadius: "4px",
            border: "1px solid rgba(245, 158, 11, 0.2)",
          }}
        >
          <div style={{ color: "#fbbf24", fontWeight: 600 }}>
            Asset Crit ({w2 * 100}%)
          </div>
          <div className="mono" style={{ color: "#fff" }}>
            {(comp.asset_criticality * 100).toFixed(1)}% (+
            {(part2 * 100).toFixed(1)})
          </div>
        </div>

        <div
          style={{
            background: "rgba(139, 92, 246, 0.08)",
            padding: "6px 8px",
            borderRadius: "4px",
            border: "1px solid rgba(139, 92, 246, 0.2)",
          }}
        >
          <div style={{ color: "#c084fc", fontWeight: 600 }}>
            ATT&CK ({w3 * 100}%)
          </div>
          <div className="mono" style={{ color: "#fff" }}>
            {(comp.attack_severity * 100).toFixed(1)}% (+
            {(part3 * 100).toFixed(1)})
          </div>
        </div>
      </div>
    </div>
  );
}
