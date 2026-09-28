import React from "react";
import {
  DATASETS,
  DOMAINS,
  getDatasetMeta,
  getDomainMeta,
} from "../utils/datasetConstants";
import { Filter, X, Check, Layers, Globe } from "lucide-react";

export default function CommandDeckFilterBar({
  selectedDatasets = [],
  selectedDomains = [],
  onToggleDataset,
  onToggleDomain,
  onClearFilters,
  datasetCounts = {},
  domainCounts = {},
}) {
  const datasetKeys = Object.keys(DATASETS);
  const domainKeys = Object.keys(DOMAINS);

  const hasActiveFilters =
    selectedDatasets.length > 0 || selectedDomains.length > 0;

  return (
    <div className="command-filter-deck">
      {/* Top Filter Header Bar */}
      <div className="filter-deck-header">
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <Filter size={13} style={{ color: "var(--cyan-bright)" }} />
          <span
            style={{
              fontSize: "11.5px",
              fontWeight: 700,
              letterSpacing: "0.04em",
              textTransform: "uppercase",
              color: "#fff",
            }}
          >
            Multi-Dataset & Domain Scope Filter
          </span>
          {hasActiveFilters && (
            <span
              className="sec-badge sec-badge-crit"
              style={{ fontSize: "10px" }}
            >
              {selectedDatasets.length + selectedDomains.length} ACTIVE
            </span>
          )}
        </div>

        {hasActiveFilters && (
          <button
            className="sec-btn sec-btn-ghost sec-btn-sm"
            onClick={onClearFilters}
            style={{
              padding: "2px 8px",
              fontSize: "10.5px",
              display: "inline-flex",
              alignItems: "center",
              gap: "4px",
            }}
          >
            <X size={11} />
            <span>Reset All Scopes</span>
          </button>
        )}
      </div>

      {/* Selector Groups */}
      <div className="filter-deck-groups">
        {/* Datasets Multi-Select */}
        <div className="filter-deck-subgroup">
          <div className="filter-subgroup-label">
            <Layers size={11} />
            <span>Datasets:</span>
          </div>

          <div className="filter-chips-list">
            <button
              className={`filter-chip ${selectedDatasets.length === 0 ? "active" : ""}`}
              onClick={() => {
                if (selectedDatasets.length > 0) {
                  // Clear datasets
                  datasetKeys.forEach((k) => {
                    if (selectedDatasets.includes(k)) onToggleDataset(k);
                  });
                }
              }}
            >
              <span>All Datasets</span>
            </button>

            {datasetKeys.map((key) => {
              const meta = DATASETS[key];
              const isSelected = selectedDatasets.includes(key);
              const count = datasetCounts[key] ?? 0;
              const Icon = meta.icon;

              return (
                <button
                  key={key}
                  className={`filter-chip ${isSelected ? "active" : ""}`}
                  onClick={() => onToggleDataset(key)}
                  style={{
                    borderColor: isSelected ? meta.color : undefined,
                    backgroundColor: isSelected ? meta.bg : undefined,
                    color: isSelected ? "#fff" : undefined,
                  }}
                  title={`Filter Command Deck by ${meta.displayName}`}
                >
                  <Icon
                    size={11}
                    style={{
                      color: isSelected ? meta.color : "var(--text-muted)",
                    }}
                  />
                  <span>{meta.displayName}</span>
                  {count > 0 && (
                    <span
                      className="chip-count"
                      style={{
                        color: isSelected ? meta.color : "var(--text-dim)",
                      }}
                    >
                      {count}
                    </span>
                  )}
                  {isSelected && (
                    <Check
                      size={11}
                      style={{ color: meta.color, marginLeft: "2px" }}
                    />
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Domains Multi-Select */}
        <div className="filter-deck-subgroup">
          <div className="filter-subgroup-label">
            <Globe size={11} />
            <span>Domains:</span>
          </div>

          <div className="filter-chips-list">
            <button
              className={`filter-chip ${selectedDomains.length === 0 ? "active" : ""}`}
              onClick={() => {
                if (selectedDomains.length > 0) {
                  domainKeys.forEach((k) => {
                    if (selectedDomains.includes(k)) onToggleDomain(k);
                  });
                }
              }}
            >
              <span>All Domains</span>
            </button>

            {domainKeys.map((key) => {
              const meta = DOMAINS[key];
              const isSelected = selectedDomains.includes(key);
              const count = domainCounts[key] ?? 0;
              const Icon = meta.icon;

              return (
                <button
                  key={key}
                  className={`filter-chip ${isSelected ? "active" : ""}`}
                  onClick={() => onToggleDomain(key)}
                  style={{
                    borderColor: isSelected ? meta.color : undefined,
                    backgroundColor: isSelected ? meta.bg : undefined,
                    color: isSelected ? "#fff" : undefined,
                  }}
                  title={`Filter Command Deck by ${meta.label}`}
                >
                  <Icon
                    size={11}
                    style={{
                      color: isSelected ? meta.color : "var(--text-muted)",
                    }}
                  />
                  <span>{meta.tag}</span>
                  <span style={{ fontSize: "10px", opacity: 0.8 }}>
                    ({meta.label})
                  </span>
                  {count > 0 && (
                    <span
                      className="chip-count"
                      style={{
                        color: isSelected ? meta.color : "var(--text-dim)",
                      }}
                    >
                      {count}
                    </span>
                  )}
                  {isSelected && (
                    <Check
                      size={11}
                      style={{ color: meta.color, marginLeft: "2px" }}
                    />
                  )}
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
