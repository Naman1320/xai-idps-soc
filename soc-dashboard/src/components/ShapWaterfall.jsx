import React from "react";
import { Activity, Shield, Cpu, Database, CheckCircle2 } from "lucide-react";
import {
  DatasetBadge,
  DomainBadge,
  getDatasetMeta,
  getDomainMeta,
} from "../utils/datasetConstants";

/**
 * SHAP Waterfall Chart Component.
 * Local feature attribution visualization showing how individual features pushed
 * the tree classifier's prediction from the baseline value toward the final attack probability.
 * Now displays the producing dataset and model engine provenance banner.
 */
export default function ShapWaterfall({
  explanation,
  mlConfidence,
  attackClass,
  datasetSource,
  domain,
  modelName,
}) {
  const dataset = explanation?.dataset_source || datasetSource || "CIC-IDS2017";
  const domainName = explanation?.domain || domain || "network";
  const model =
    explanation?.model_name ||
    modelName ||
    "Random Forest / XGBoost Multi-Class Ensemble";
  const meta = getDatasetMeta(dataset);
  const domainMeta = getDomainMeta(domainName);

  if (
    !explanation ||
    !explanation.features ||
    explanation.features.length === 0
  ) {
    return (
      <div
        className="panel"
        style={{
          padding: "20px",
          textAlign: "center",
          color: "var(--text-muted)",
        }}
      >
        <p style={{ fontSize: "12px" }}>
          No SHAP local explainability attributions recorded for this flow.
        </p>
      </div>
    );
  }

  const features = explanation.features;
  const maxAbsShap = Math.max(
    ...features.map((f) => Math.abs(f.shap_value)),
    0.1,
  );
  const baseValue = explanation.base_value || 0.1;

  return (
    <div className="panel">
      {/* Panel Header */}
      <div className="panel-header">
        <div className="panel-title">
          <Activity size={14} style={{ color: "var(--cyan-bright)" }} />
          <span>SHAP TreeExplainer Local Attribution Matrix</span>
        </div>
        <div
          style={{
            display: "flex",
            gap: "12px",
            fontSize: "11px",
            fontFamily: "var(--font-mono)",
          }}
        >
          <span
            style={{
              display: "flex",
              alignItems: "center",
              gap: "4px",
              color: "var(--signal-crit)",
            }}
          >
            <span
              style={{
                width: "6px",
                height: "6px",
                background: "var(--signal-crit)",
                borderRadius: "1px",
              }}
            ></span>
            + Push Attack
          </span>
          <span
            style={{
              display: "flex",
              alignItems: "center",
              gap: "4px",
              color: "var(--signal-low)",
            }}
          >
            <span
              style={{
                width: "6px",
                height: "6px",
                background: "var(--signal-low)",
                borderRadius: "1px",
              }}
            ></span>
            - Push Benign
          </span>
        </div>
      </div>

      <div
        className="panel-body"
        style={{ display: "flex", flexDirection: "column", gap: "10px" }}
      >
        {/* Model & Dataset Origin Provenance Banner (Required) */}
        <div className="model-provenance-banner">
          <div className="provenance-left">
            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <Cpu size={13} style={{ color: "var(--cyan-bright)" }} />
              <span className="provenance-label">PRODUCING MODEL:</span>
              <strong className="provenance-val" style={{ color: "#fff" }}>
                {model}
              </strong>
            </div>

            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                marginTop: "2px",
              }}
            >
              <Database size={12} style={{ color: meta.color }} />
              <span className="provenance-label">DATASET SOURCE:</span>
              <DatasetBadge dataset={dataset} size="sm" showIcon={false} />
              <DomainBadge domain={domainName} size="sm" />
            </div>
          </div>

          <div className="provenance-right">
            <span
              className="sec-badge sec-badge-active"
              style={{ fontSize: "9.5px" }}
            >
              EXACT TreeSHAP
            </span>
            <div
              style={{
                fontSize: "10.5px",
                color: "var(--text-muted)",
                fontFamily: "var(--font-mono)",
                marginTop: "2px",
              }}
            >
              Baseline E[f(x)] = {baseValue.toFixed(2)}
            </div>
          </div>
        </div>

        {/* Confidence Progress Header */}
        <div
          style={{
            fontSize: "11px",
            color: "var(--text-muted)",
            fontFamily: "var(--font-mono)",
            display: "flex",
            justifyContent: "space-between",
          }}
        >
          <span>
            Prior Base Probability:{" "}
            <strong style={{ color: "#fff" }}>{baseValue.toFixed(2)}</strong>
          </span>
          <span>
            Posterior Predicted Confidence:{" "}
            <strong style={{ color: "var(--cyan-bright)" }}>
              {mlConfidence !== undefined
                ? `${(mlConfidence * 100).toFixed(1)}%`
                : "95.0%"}
            </strong>{" "}
            [{attackClass}]
          </span>
        </div>

        {/* Waterfall Bars */}
        <div style={{ display: "flex", flexDirection: "column", gap: "5px" }}>
          {features.map((item, idx) => {
            const isPos = item.shap_value >= 0;
            const barWidthPct = Math.min(
              100,
              Math.round((Math.abs(item.shap_value) / maxAbsShap) * 48),
            );

            return (
              <div key={item.id || idx} className="waterfall-row">
                <div style={{ minWidth: 0 }}>
                  <div
                    className="waterfall-feature-name"
                    title={item.feature_name}
                  >
                    {item.feature_name}
                  </div>
                  <div className="waterfall-feature-val">
                    Observed:{" "}
                    {item.feature_value !== null &&
                    item.feature_value !== undefined
                      ? Number(item.feature_value).toLocaleString()
                      : "N/A"}
                  </div>
                </div>

                {/* Bar track centered at 50% */}
                <div className="waterfall-bar-track">
                  <div className="waterfall-center-line"></div>
                  <div
                    className={`waterfall-bar ${isPos ? "positive" : "negative"}`}
                    style={{
                      width: `${barWidthPct}%`,
                    }}
                  ></div>
                </div>

                <div className={`waterfall-shap-val ${isPos ? "pos" : "neg"}`}>
                  {isPos
                    ? `+${item.shap_value.toFixed(3)}`
                    : item.shap_value.toFixed(3)}
                </div>
              </div>
            );
          })}
        </div>

        {/* Analyst Narrative Box */}
        {explanation.plain_language && (
          <div className="narrative-box" style={{ marginTop: "4px" }}>
            <div className="narrative-title">
              <Shield size={13} style={{ color: "var(--cyan-bright)" }} />
              <span>Analyst Rationale ({meta.displayName} Telemetry)</span>
            </div>
            <p className="narrative-text">
              {explanation.plain_language.summary}
            </p>
            {explanation.plain_language.recommended_action && (
              <div
                style={{
                  marginTop: "8px",
                  paddingTop: "8px",
                  borderTop: "1px solid var(--border-hairline)",
                }}
              >
                <span
                  style={{
                    fontSize: "10.5px",
                    fontWeight: 600,
                    color: "var(--cyan-bright)",
                    textTransform: "uppercase",
                    fontFamily: "var(--font-mono)",
                  }}
                >
                  Recommended Containment Action:{" "}
                </span>
                <span
                  style={{ fontSize: "12px", color: "var(--text-primary)" }}
                >
                  {explanation.plain_language.recommended_action}
                </span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
