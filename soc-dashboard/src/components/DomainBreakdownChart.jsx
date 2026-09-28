import React, { useState } from "react";
import { DOMAINS, getDomainMeta } from "../utils/datasetConstants";
import { PieChart, Server, Wifi, Factory, HeartPulse } from "lucide-react";

export default function DomainBreakdownChart({
  domainBreakdown = {},
  selectedDomains = [],
  onToggleDomain,
}) {
  const [hoveredDomain, setHoveredDomain] = useState(null);

  // Domains to display: network, iot, iomt, iiot
  const domainKeys = ["network", "iot", "iiot", "iomt"];

  // Sum total
  const total =
    domainKeys.reduce((acc, k) => acc + (domainBreakdown[k] || 0), 0) || 1;

  // Compute donut segments
  const radius = 42;
  const circumference = 2 * Math.PI * radius; // ~263.89

  let accumulatedPercent = 0;
  const segments = domainKeys.map((key) => {
    const count = domainBreakdown[key] || 0;
    const percent = count / total;
    const strokeDasharray = `${percent * circumference} ${circumference}`;
    const strokeDashoffset = -accumulatedPercent * circumference;
    accumulatedPercent += percent;

    return {
      key,
      count,
      percent,
      percentageFormatted: (percent * 100).toFixed(1),
      strokeDasharray,
      strokeDashoffset,
      meta: getDomainMeta(key),
    };
  });

  const activeSegment = hoveredDomain
    ? segments.find((s) => s.key === hoveredDomain)
    : null;

  return (
    <div className="panel" style={{ height: "100%" }}>
      <div className="panel-header">
        <div className="panel-title">
          <PieChart size={14} style={{ color: "var(--cyan-bright)" }} />
          <span>Domain Telemetry Breakdown</span>
        </div>
        <span className="panel-badge">4 DOMAINS MONITORED</span>
      </div>

      <div
        className="panel-body"
        style={{ display: "flex", flexDirection: "column", gap: "14px" }}
      >
        {/* Top: Donut SVG + Center Stat */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "20px",
            padding: "6px 0",
          }}
        >
          <div
            style={{
              position: "relative",
              width: "124px",
              height: "124px",
              flexShrink: 0,
            }}
          >
            <svg
              viewBox="0 0 100 100"
              style={{
                width: "100%",
                height: "100%",
                transform: "rotate(-90deg)",
                overflow: "visible",
              }}
            >
              {/* Background circle */}
              <circle
                cx="50"
                cy="50"
                r={radius}
                fill="none"
                stroke="var(--bg-inset)"
                strokeWidth="11"
              />

              {/* Segments */}
              {segments.map((seg) => {
                const isHovered = hoveredDomain === seg.key;
                const isSelected = selectedDomains.includes(seg.key);

                return (
                  <circle
                    key={seg.key}
                    cx="50"
                    cy="50"
                    r={radius}
                    fill="none"
                    stroke={seg.meta.color}
                    strokeWidth={isHovered ? "13" : "10"}
                    strokeDasharray={seg.strokeDasharray}
                    strokeDashoffset={seg.strokeDashoffset}
                    strokeLinecap="butt"
                    style={{
                      cursor: "pointer",
                      transition: "stroke-width 0.15s ease, opacity 0.15s ease",
                      opacity:
                        selectedDomains.length > 0 && !isSelected ? 0.35 : 1,
                      filter: isHovered
                        ? `drop-shadow(0 0 6px ${seg.meta.color})`
                        : undefined,
                    }}
                    onMouseEnter={() => setHoveredDomain(seg.key)}
                    onMouseLeave={() => setHoveredDomain(null)}
                    onClick={() => onToggleDomain && onToggleDomain(seg.key)}
                  />
                );
              })}
            </svg>

            {/* Central Readout */}
            <div
              style={{
                position: "absolute",
                inset: 0,
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
                pointerEvents: "none",
                textAlign: "center",
              }}
            >
              <span
                style={{
                  fontSize: "15px",
                  fontWeight: 800,
                  fontFamily: "var(--font-mono)",
                  color: activeSegment ? activeSegment.meta.color : "#fff",
                  lineHeight: 1.1,
                }}
              >
                {activeSegment
                  ? `${activeSegment.percentageFormatted}%`
                  : Number(total).toLocaleString()}
              </span>
              <span
                style={{
                  fontSize: "9px",
                  textTransform: "uppercase",
                  letterSpacing: "0.06em",
                  color: "var(--text-muted)",
                  marginTop: "1px",
                }}
              >
                {activeSegment ? activeSegment.meta.tag : "TOTAL FLOWS"}
              </span>
            </div>
          </div>

          {/* Quick Domain Distribution Bar */}
          <div
            style={{
              flex: 1,
              display: "flex",
              flexDirection: "column",
              gap: "8px",
            }}
          >
            {domainKeys.map((key) => {
              const count = domainBreakdown[key] || 0;
              const pct = ((count / total) * 100).toFixed(1);
              const meta = getDomainMeta(key);
              const isSelected = selectedDomains.includes(key);
              const isHovered = hoveredDomain === key;
              const Icon = meta.icon;

              return (
                <div
                  key={key}
                  onClick={() => onToggleDomain && onToggleDomain(key)}
                  onMouseEnter={() => setHoveredDomain(key)}
                  onMouseLeave={() => setHoveredDomain(null)}
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "2px",
                    padding: "4px 6px",
                    borderRadius: "var(--radius-xs)",
                    cursor: "pointer",
                    background: isSelected
                      ? meta.bg
                      : isHovered
                        ? "var(--bg-inset)"
                        : "transparent",
                    border: `1px solid ${isSelected ? meta.border : "transparent"}`,
                    transition: "all 0.12s ease",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      fontSize: "11px",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "5px",
                      }}
                    >
                      <Icon size={11} style={{ color: meta.color }} />
                      <span style={{ color: "#fff", fontWeight: 600 }}>
                        {meta.label}
                      </span>
                      <span
                        style={{
                          color: "var(--text-dim)",
                          fontSize: "10px",
                          fontFamily: "var(--font-mono)",
                        }}
                      >
                        [{meta.tag}]
                      </span>
                    </div>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "6px",
                        fontFamily: "var(--font-mono)",
                      }}
                    >
                      <span style={{ color: meta.color, fontWeight: 700 }}>
                        {pct}%
                      </span>
                      <span
                        style={{ color: "var(--text-muted)", fontSize: "10px" }}
                      >
                        ({count})
                      </span>
                    </div>
                  </div>

                  {/* Horizontal mini-bar */}
                  <div
                    style={{
                      width: "100%",
                      height: "4px",
                      background: "var(--border-hairline)",
                      borderRadius: "2px",
                      overflow: "hidden",
                    }}
                  >
                    <div
                      style={{
                        width: `${pct}%`,
                        height: "100%",
                        backgroundColor: meta.color,
                        transition: "width 0.4s ease",
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Informational Subtext */}
        <div
          style={{
            padding: "8px 10px",
            background: "var(--bg-inset)",
            borderRadius: "var(--radius-xs)",
            border: "1px solid var(--border-hairline)",
            fontSize: "11px",
            color: "var(--text-secondary)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <span>Heterogeneous edge sensor ingestion online</span>
          <span
            style={{
              color: "var(--cyan-bright)",
              fontFamily: "var(--font-mono)",
              fontSize: "10.5px",
            }}
          >
            {selectedDomains.length > 0
              ? `FILTER: ${selectedDomains.join(", ").toUpperCase()}`
              : "ALL DOMAINS ACTIVE"}
          </span>
        </div>
      </div>
    </div>
  );
}
