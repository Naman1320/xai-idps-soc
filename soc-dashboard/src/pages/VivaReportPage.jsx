import React, { useState, useEffect } from "react";
import { api } from "../api/client";
import {
  Download,
  Target,
  BarChart3,
  GraduationCap,
  FileText,
  CheckCircle2,
  BookOpen,
  Award,
  Loader2,
} from "lucide-react";

export default function VivaReportPage() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadReport() {
      try {
        setLoading(true);
        const data = await api.getVivaReport();
        setReport(data);
      } catch (err) {
        console.error("Failed to load report:", err);
      } finally {
        setLoading(false);
      }
    }
    loadReport();
  }, []);

  const handleDownloadCsv = () => {
    window.open("/api/v1/reports/export-csv", "_blank");
  };

  if (loading) {
    return (
      <div className="panel" style={{ padding: "48px", textAlign: "center" }}>
        <div
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "8px",
            color: "var(--text-muted)",
            fontSize: "13px",
            fontFamily: "var(--font-mono)",
          }}
        >
          <Loader2
            size={16}
            className="spin"
            style={{ color: "var(--cyan-bright)" }}
          />
          <span>
            Generating project defense & empirical evaluation dossier...
          </span>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
      {/* Header */}
      <div className="panel" style={{ padding: "20px 24px" }}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            flexWrap: "wrap",
            gap: "16px",
          }}
        >
          <div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                marginBottom: "4px",
              }}
            >
              <span
                className="sec-badge sec-badge-neutral"
                style={{ fontFamily: "var(--font-mono)" }}
              >
                PROJECT DEFENSE DOSSIER
              </span>
              <span
                className="sec-badge sec-badge-info"
                style={{ fontFamily: "var(--font-mono)" }}
              >
                EVALUATION BENCHMARK
              </span>
            </div>
            <h3
              style={{
                color: "var(--text-primary)",
                fontSize: "1.2rem",
                fontWeight: 700,
                margin: 0,
              }}
            >
              Viva Presentation Dossier & Empirical Defense Summary
            </h3>
            <p
              style={{
                fontSize: "12px",
                color: "var(--text-muted)",
                margin: "4px 0 0 0",
              }}
            >
              Synthesis of the literature gap, multi-modal pipeline
              architecture, empirical benchmarks, and examiner defense
              cheat-sheet.
            </p>
          </div>

          <button
            className="sec-btn sec-btn-primary"
            onClick={handleDownloadCsv}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "6px",
              padding: "8px 16px",
            }}
          >
            <Download size={13} />
            <span>Export Telemetry CSV</span>
          </button>
        </div>
      </div>

      {/* Research Gap Statement Card */}
      <div
        className="panel"
        style={{ borderLeft: "3px solid var(--cyan-bright)" }}
      >
        <div
          className="panel-header"
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <Target size={15} style={{ color: "var(--cyan-bright)" }} />
            <span className="panel-title">
              THE RESEARCH & PROBLEM GAP ADDRESSED
            </span>
          </div>
          <span
            className="sec-badge sec-badge-neutral"
            style={{ fontFamily: "var(--font-mono)" }}
          >
            Literature Validated (17 Papers)
          </span>
        </div>

        <p
          style={{
            fontSize: "13px",
            color: "var(--text-secondary)",
            lineHeight: 1.6,
            marginBottom: "16px",
          }}
        >
          {report?.core_research_gap}
        </p>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
            gap: "12px",
          }}
        >
          {report?.key_novelties?.map((nov, idx) => (
            <div
              key={idx}
              style={{
                background: "var(--surface-sunken)",
                border: "1px solid var(--border-hairline)",
                borderRadius: "4px",
                padding: "12px 14px",
              }}
            >
              <div
                style={{
                  color: "var(--cyan-bright)",
                  fontWeight: 700,
                  fontSize: "11px",
                  textTransform: "uppercase",
                  letterSpacing: "0.04em",
                  marginBottom: "4px",
                  fontFamily: "var(--font-mono)",
                }}
              >
                Contribution #{idx + 1}
              </div>
              <p
                style={{
                  fontSize: "12px",
                  color: "var(--text-muted)",
                  lineHeight: 1.4,
                  margin: 0,
                }}
              >
                {nov}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Empirical Benchmark Table */}
      <div className="panel">
        <div
          className="panel-header"
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <BarChart3 size={15} style={{ color: "var(--cyan-bright)" }} />
            <span className="panel-title">
              EMPIRICAL BENCHMARK METRICS VS. TARGETS
            </span>
          </div>
          <span
            className="sec-badge sec-badge-info"
            style={{ fontFamily: "var(--font-mono)" }}
          >
            Datasets: {report?.datasets_evaluated}
          </span>
        </div>

        <div
          className="telemetry-ribbon"
          style={{ border: "none", background: "transparent", padding: 0 }}
        >
          <div className="telemetry-stat">
            <div className="stat-label">Macro-Averaged F1</div>
            <div
              className="stat-value"
              style={{ color: "var(--emerald-bright)" }}
            >
              {report?.empirical_results?.macro_f1_score}
            </div>
            <div className="stat-sub">Target ≥ 90.0%</div>
          </div>

          <div className="telemetry-stat">
            <div className="stat-label">False Positive Rate (FPR)</div>
            <div className="stat-value" style={{ color: "var(--blue-bright)" }}>
              {report?.empirical_results?.false_positive_rate}
            </div>
            <div className="stat-sub">Baseline: 4.8%</div>
          </div>

          <div className="telemetry-stat">
            <div className="stat-label">Precision@10 Prioritization</div>
            <div
              className="stat-value"
              style={{ color: "var(--amber-bright)" }}
            >
              {report?.empirical_results?.precision_at_10_gain}
            </div>
            <div className="stat-sub">vs. Confidence-Only</div>
          </div>

          <div className="telemetry-stat">
            <div className="stat-label">Ingestion Latency</div>
            <div className="stat-value" style={{ color: "var(--cyan-bright)" }}>
              {report?.empirical_results?.ingestion_latency}
            </div>
            <div className="stat-sub">Sub-50ms Real-Time</div>
          </div>
        </div>
      </div>

      {/* Viva Examiner Q&A Flashcards */}
      <div className="panel">
        <div
          className="panel-header"
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <GraduationCap size={15} style={{ color: "var(--cyan-bright)" }} />
            <span className="panel-title">VIVA DEFENSE Q&A PREPARATION</span>
          </div>
          <span
            className="sec-badge sec-badge-neutral"
            style={{ fontFamily: "var(--font-mono)" }}
          >
            Examiner Reference
          </span>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
          {report?.viva_sample_questions?.map((item, idx) => (
            <div
              key={idx}
              style={{
                background: "var(--surface-sunken)",
                border: "1px solid var(--border-hairline)",
                borderRadius: "4px",
                padding: "14px 16px",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                  marginBottom: "8px",
                }}
              >
                <span
                  className="sec-badge sec-badge-critical"
                  style={{ fontSize: "10px", fontFamily: "var(--font-mono)" }}
                >
                  Q{idx + 1}
                </span>
                <strong
                  style={{ color: "var(--text-primary)", fontSize: "13px" }}
                >
                  {item.q}
                </strong>
              </div>
              <p
                style={{
                  fontSize: "12px",
                  color: "var(--text-muted)",
                  lineHeight: 1.6,
                  paddingLeft: "28px",
                  margin: 0,
                }}
              >
                <strong style={{ color: "var(--cyan-bright)" }}>
                  Defense Formulation:{" "}
                </strong>
                {item.a}
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
