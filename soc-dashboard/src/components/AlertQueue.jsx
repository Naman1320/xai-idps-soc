import React, { useState, useEffect } from "react";
import { api } from "../api/client";
import {
  DATASETS,
  DOMAINS,
  DatasetBadge,
  DomainBadge,
} from "../utils/datasetConstants";
import { Search, Zap, ArrowUpDown, Filter, ShieldAlert } from "lucide-react";

export default function AlertQueue({ onSelectAlert, refreshTrigger }) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);

  // Filters
  const [search, setSearch] = useState("");
  const [dataset, setDataset] = useState("");
  const [domain, setDomain] = useState("");
  const [attackClass, setAttackClass] = useState("");
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [minRisk, setMinRisk] = useState("");
  const [sortBy, setSortBy] = useState("detected_at"); // Default: sorted by timestamp into ONE unified queue
  const [order, setOrder] = useState("desc");

  const loadAlerts = async () => {
    try {
      setLoading(true);
      const res = await api.getAlerts({
        page,
        limit: 15,
        search,
        dataset: dataset || undefined,
        domain: domain || undefined,
        attack_class: attackClass || undefined,
        status: status || undefined,
        severity: severity || undefined,
        min_risk: minRisk ? parseFloat(minRisk) : undefined,
        sort_by: sortBy,
        order,
      });
      setAlerts(res.alerts || []);
      setTotal(res.total || 0);
      setPages(res.pages || 1);
    } catch (err) {
      console.error("Failed to load alert queue:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, [
    page,
    dataset,
    domain,
    attackClass,
    status,
    severity,
    minRisk,
    sortBy,
    order,
    refreshTrigger,
  ]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    loadAlerts();
  };

  const handleResetFilters = () => {
    setSearch("");
    setDataset("");
    setDomain("");
    setAttackClass("");
    setStatus("");
    setSeverity("");
    setMinRisk("");
    setPage(1);
  };

  const handleQuickStatus = async (e, alertId, newStatus) => {
    e.stopPropagation();
    try {
      await api.updateAlertStatus(alertId, newStatus);
      setAlerts((prev) =>
        prev.map((a) => (a.id === alertId ? { ...a, status: newStatus } : a)),
      );
    } catch (err) {
      alert("Error updating status: " + err.message);
    }
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

  const getStatusBadge = (st) => {
    const s = (st || "").toLowerCase();
    let color = "#94a3b8";
    if (s === "new") color = "var(--cyan-bright)";
    if (s === "investigating") color = "#fbbf24";
    if (s === "resolved") color = "#34d399";
    if (s === "dismissed" || s === "closed") color = "#64748b";

    return (
      <span
        className="sec-badge"
        style={{
          backgroundColor: `${color}14`,
          color,
          border: `1px solid ${color}40`,
          fontSize: "10px",
        }}
      >
        {st.toUpperCase()}
      </span>
    );
  };

  const hasFilters =
    dataset || domain || attackClass || status || severity || minRisk || search;

  return (
    <div className="panel">
      {/* Header */}
      <div className="panel-header" style={{ flexWrap: "wrap", gap: "10px" }}>
        <div>
          <div className="panel-title">
            <ShieldAlert size={15} style={{ color: "var(--signal-crit)" }} />
            <span>Unified Multi-Dataset Intrusion Alert Queue</span>
          </div>
          <p
            style={{
              fontSize: "11px",
              color: "var(--text-muted)",
              marginTop: "2px",
            }}
          >
            Single chronological stream spanning Network, IoT, IIoT, and Medical
            telemetry sources.
          </p>
        </div>

        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
          <button
            className="sec-btn sec-btn-ghost sec-btn-sm"
            onClick={() =>
              setSortBy((prev) =>
                prev === "detected_at" ? "risk_score" : "detected_at",
              )
            }
            title="Toggle sort between Timestamp and Risk Score"
            style={{ fontSize: "11px", gap: "4px" }}
          >
            <ArrowUpDown size={11} />
            <span>
              Sorted by:{" "}
              {sortBy === "detected_at"
                ? "Timestamp (Newest)"
                : "Risk Score (Highest)"}
            </span>
          </button>

          <span
            className="sec-badge sec-badge-neutral"
            style={{ fontSize: "11px" }}
          >
            Total:{" "}
            <strong style={{ color: "#fff", marginLeft: "3px" }}>
              {Number(total).toLocaleString()}
            </strong>
          </span>

          <button
            className="sec-btn sec-btn-secondary sec-btn-sm"
            onClick={loadAlerts}
          >
            ⟳ Refresh
          </button>
        </div>
      </div>

      {/* Filter Controls Bar */}
      <form onSubmit={handleSearchSubmit} className="alert-queue-filter-bar">
        {/* Search */}
        <div
          style={{ position: "relative", flex: "1 1 200px", minWidth: "180px" }}
        >
          <input
            type="text"
            className="sec-input"
            placeholder="Search IP, vector, dataset..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{ width: "100%", paddingLeft: "28px", fontSize: "11.5px" }}
          />
          <Search
            size={12}
            style={{
              position: "absolute",
              left: "9px",
              top: "50%",
              transform: "translateY(-50%)",
              color: "var(--text-muted)",
            }}
          />
        </div>

        {/* Dataset Filter Dropdown (Required) */}
        <select
          className="sec-select"
          value={dataset}
          onChange={(e) => {
            setDataset(e.target.value);
            setPage(1);
          }}
          title="Filter by Dataset Source"
        >
          <option value="">All Datasets (Unified)</option>
          {Object.keys(DATASETS).map((k) => (
            <option key={k} value={k}>
              {DATASETS[k].displayName} ({DATASETS[k].domain.toUpperCase()})
            </option>
          ))}
        </select>

        {/* Domain Filter Dropdown (Required) */}
        <select
          className="sec-select"
          value={domain}
          onChange={(e) => {
            setDomain(e.target.value);
            setPage(1);
          }}
          title="Filter by Domain"
        >
          <option value="">All Domains</option>
          {Object.keys(DOMAINS).map((k) => (
            <option key={k} value={k}>
              {DOMAINS[k].label} [{DOMAINS[k].tag}]
            </option>
          ))}
        </select>

        {/* Attack Class Dropdown */}
        <select
          className="sec-select"
          value={attackClass}
          onChange={(e) => {
            setAttackClass(e.target.value);
            setPage(1);
          }}
        >
          <option value="">All Attack Types</option>
          <option value="DDoS">DDoS</option>
          <option value="DoS/DDoS">DoS / DDoS</option>
          <option value="Recon">Reconnaissance</option>
          <option value="Spoofing">Spoofing</option>
          <option value="Brute Force">Brute Force</option>
          <option value="Web">Web Attack</option>
          <option value="Malware/Botnet/Mirai">Malware / Botnet / Mirai</option>
          <option value="APT/Other">APT / Other</option>
          <option value="Benign">Benign</option>
        </select>

        {/* Status Dropdown */}
        <select
          className="sec-select"
          value={status}
          onChange={(e) => {
            setStatus(e.target.value);
            setPage(1);
          }}
        >
          <option value="">All Statuses</option>
          <option value="new">New</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
          <option value="dismissed">Dismissed</option>
          <option value="closed">Closed</option>
        </select>

        {/* Min Risk Score */}
        <select
          className="sec-select"
          value={minRisk}
          onChange={(e) => {
            setMinRisk(e.target.value);
            setPage(1);
          }}
        >
          <option value="">Min Risk Score</option>
          <option value="0.75">Critical (≥ 0.75)</option>
          <option value="0.50">High (≥ 0.50)</option>
          <option value="0.30">Medium (≥ 0.30)</option>
        </select>

        <button type="submit" className="sec-btn sec-btn-primary sec-btn-sm">
          Filter
        </button>

        {hasFilters && (
          <button
            type="button"
            className="sec-btn sec-btn-ghost sec-btn-sm"
            onClick={handleResetFilters}
            title="Clear all active filters"
          >
            Reset
          </button>
        )}
      </form>

      {/* Unified Table */}
      <div className="panel-body-flush sec-table-container">
        <table className="sec-table">
          <thead>
            <tr>
              <th style={{ width: "100px" }}>Priority</th>
              <th style={{ width: "130px" }}>Dataset</th>
              <th style={{ width: "70px" }}>Domain</th>
              <th>Attack Class</th>
              <th>Source IP</th>
              <th>Destination</th>
              <th style={{ width: "85px" }}>ML Conf</th>
              <th style={{ width: "105px" }}>MITRE ATT&CK</th>
              <th style={{ width: "90px" }}>Status</th>
              <th style={{ width: "110px" }}>Timestamp</th>
              <th style={{ width: "85px", textAlign: "right" }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td
                  colSpan="11"
                  style={{
                    textAlign: "center",
                    padding: "36px",
                    color: "var(--text-muted)",
                  }}
                >
                  Loading unified alert telemetry stream...
                </td>
              </tr>
            ) : alerts.length === 0 ? (
              <tr>
                <td
                  colSpan="11"
                  style={{
                    textAlign: "center",
                    padding: "36px",
                    color: "var(--text-muted)",
                  }}
                >
                  No alerts match the selected criteria.
                </td>
              </tr>
            ) : (
              alerts.map((alert) => (
                <tr key={alert.id} onClick={() => onSelectAlert(alert.id)}>
                  {/* Priority / Risk */}
                  <td>{getRiskBadge(alert.risk_score)}</td>

                  {/* Dataset Column with icon/tag (Required) */}
                  <td>
                    <DatasetBadge
                      dataset={alert.dataset_source}
                      size="sm"
                      showIcon={true}
                    />
                  </td>

                  {/* Domain Column (Required) */}
                  <td>
                    <DomainBadge domain={alert.domain} size="sm" />
                  </td>

                  {/* Attack Class */}
                  <td>
                    <strong style={{ color: "#fff" }}>
                      {alert.attack_class}
                    </strong>
                  </td>

                  {/* Source IP */}
                  <td>
                    <span
                      className="mono-ip"
                      style={{ color: "var(--cyan-bright)" }}
                    >
                      {alert.source_ip}
                    </span>
                  </td>

                  {/* Destination */}
                  <td>
                    <span className="mono-ip">
                      {alert.dest_ip}:{alert.dest_port || "Any"}
                    </span>
                  </td>

                  {/* ML Confidence */}
                  <td>
                    <span className="mono-time" style={{ color: "#60a5fa" }}>
                      {(alert.ml_confidence * 100).toFixed(1)}%
                    </span>
                  </td>

                  {/* MITRE */}
                  <td>
                    {alert.mitre_technique_id ? (
                      <span
                        className="sec-badge sec-badge-mitre"
                        title={alert.mitre_technique_name}
                      >
                        {alert.mitre_technique_id}
                      </span>
                    ) : (
                      <span style={{ color: "var(--text-dim)" }}>—</span>
                    )}
                  </td>

                  {/* Status */}
                  <td>{getStatusBadge(alert.status)}</td>

                  {/* Timestamp */}
                  <td>
                    <span
                      className="mono-time"
                      style={{
                        fontSize: "11px",
                        color: "var(--text-secondary)",
                      }}
                    >
                      {new Date(alert.detected_at).toLocaleTimeString([], {
                        hour: "2-digit",
                        minute: "2-digit",
                        second: "2-digit",
                      })}
                    </span>
                  </td>

                  {/* Actions */}
                  <td style={{ textAlign: "right" }}>
                    <div style={{ display: "inline-flex", gap: "4px" }}>
                      <button
                        className="sec-btn sec-btn-ghost sec-btn-sm"
                        style={{ padding: "2px 6px", fontSize: "10.5px" }}
                        title="View SHAP Explanation & Model Attribution"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectAlert(alert.id);
                        }}
                      >
                        Explain
                      </button>
                      {alert.status === "new" && (
                        <button
                          className="sec-btn sec-btn-primary sec-btn-sm"
                          style={{ padding: "2px 5px", fontSize: "10.5px" }}
                          title="Mark Investigating"
                          onClick={(e) =>
                            handleQuickStatus(e, alert.id, "investigating")
                          }
                        >
                          <Zap size={10} />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      {pages > 1 && (
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            padding: "12px 16px",
            borderTop: "1px solid var(--border-hairline)",
            backgroundColor: "var(--bg-surface-elevated)",
          }}
        >
          <span
            style={{
              fontSize: "11.5px",
              color: "var(--text-muted)",
              fontFamily: "var(--font-mono)",
            }}
          >
            Page {page} of {pages} ({Number(total).toLocaleString()} total
            records)
          </span>
          <div style={{ display: "flex", gap: "8px" }}>
            <button
              className="sec-btn sec-btn-secondary sec-btn-sm"
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
            >
              Previous
            </button>
            <button
              className="sec-btn sec-btn-secondary sec-btn-sm"
              disabled={page >= pages}
              onClick={() => setPage((p) => Math.min(pages, p + 1))}
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
