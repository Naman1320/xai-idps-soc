import React, { useState, useEffect } from 'react';
import { api } from '../api/client';
import { Search, Zap } from 'lucide-react';

export default function AlertQueue({ onSelectAlert, refreshTrigger }) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);

  // Filters
  const [search, setSearch] = useState('');
  const [attackClass, setAttackClass] = useState('');
  const [status, setStatus] = useState('');
  const [severity, setSeverity] = useState('');
  const [minRisk, setMinRisk] = useState('');

  const loadAlerts = async () => {
    try {
      setLoading(true);
      const res = await api.getAlerts({
        page,
        limit: 15,
        search,
        attack_class: attackClass,
        status,
        severity,
        min_risk: minRisk ? parseFloat(minRisk) : undefined,
        sort_by: 'risk_score',
        order: 'desc',
      });
      setAlerts(res.alerts || []);
      setTotal(res.total || 0);
      setPages(res.pages || 1);
    } catch (err) {
      console.error('Failed to load alert queue:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, [page, attackClass, status, severity, minRisk, refreshTrigger]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    loadAlerts();
  };

  const handleQuickStatus = async (e, alertId, newStatus) => {
    e.stopPropagation();
    try {
      await api.updateAlertStatus(alertId, newStatus);
      setAlerts((prev) =>
        prev.map((a) => (a.id === alertId ? { ...a, status: newStatus } : a))
      );
    } catch (err) {
      alert('Error updating status: ' + err.message);
    }
  };

  const getRiskBadge = (score) => {
    if (score >= 0.75) return <span className="badge badge-critical">{(score * 100).toFixed(0)} CRITICAL</span>;
    if (score >= 0.50) return <span className="badge badge-high">{(score * 100).toFixed(0)} HIGH</span>;
    if (score >= 0.30) return <span className="badge badge-medium">{(score * 100).toFixed(0)} MEDIUM</span>;
    return <span className="badge badge-low">{(score * 100).toFixed(0)} LOW</span>;
  };

  const getStatusBadge = (st) => {
    const s = (st || '').toLowerCase();
    let color = '#94a3b8';
    if (s === 'new') color = 'var(--cyan-bright)';
    if (s === 'investigating') color = '#fbbf24';
    if (s === 'resolved') color = '#34d399';
    if (s === 'dismissed' || s === 'closed') color = '#64748b';

    return (
      <span className="badge" style={{ backgroundColor: `${color}18`, color, border: `1px solid ${color}40` }}>
        {st.toUpperCase()}
      </span>
    );
  };

  return (
    <div className="card">
      <div className="card-header">
        <div>
          <h3 className="card-title">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ color: 'var(--signal-crit)' }}>
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
              <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
            <span>Intrusion Alert Triage Queue</span>
          </h3>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Sorted by composite risk score: <strong style={{ color: '#fff' }}>w₁·Confidence + w₂·Asset + w₃·Severity</strong>
          </p>
        </div>

        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span className="badge badge-status">
            Total: <strong style={{ color: '#fff' }}>{total}</strong> alerts
          </span>
          <button className="btn btn-secondary btn-sm" onClick={loadAlerts}>
            ⟳ Refresh
          </button>
        </div>
      </div>

      {/* Filter Controls Bar */}
      <form onSubmit={handleSearchSubmit} className="filter-bar">
        <input
          type="text"
          className="input-field"
          placeholder="Search by IP, attack, or technique..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ width: '260px' }}
        />

        <select
          className="select-field"
          value={attackClass}
          onChange={(e) => {
            setAttackClass(e.target.value);
            setPage(1);
          }}
        >
          <option value="">All Attack Types</option>
          <option value="DDoS">DDoS</option>
          <option value="DoS Hulk">DoS Hulk</option>
          <option value="PortScan">PortScan</option>
          <option value="SSH-Patator">SSH-Patator</option>
          <option value="FTP-Patator">FTP-Patator</option>
          <option value="Web Attack">Web Attack</option>
          <option value="Botnet">Botnet</option>
          <option value="Infiltration">Infiltration</option>
          <option value="Benign">Benign</option>
        </select>

        <select
          className="select-field"
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

        <select
          className="select-field"
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

        <button type="submit" className="btn btn-secondary btn-sm">
          Filter
        </button>
      </form>

      {/* Table */}
      <div className="table-container">
        <table className="soc-table">
          <thead>
            <tr>
              <th>Risk Score</th>
              <th>Attack Class</th>
              <th>Source IP</th>
              <th>Destination</th>
              <th>Confidence</th>
              <th>MITRE ATT&CK</th>
              <th>Status</th>
              <th>Detected</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="9" style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>
                  Loading alerts...
                </td>
              </tr>
            ) : alerts.length === 0 ? (
              <tr>
                <td colSpan="9" style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>
                  No alerts match the selected criteria.
                </td>
              </tr>
            ) : (
              alerts.map((alert) => (
                <tr key={alert.id} onClick={() => onSelectAlert(alert.id)}>
                  <td>{getRiskBadge(alert.risk_score)}</td>
                  <td>
                    <strong style={{ color: '#fff' }}>{alert.attack_class}</strong>
                  </td>
                  <td className="mono" style={{ color: 'var(--cyan-bright)' }}>
                    {alert.source_ip}
                  </td>
                  <td className="mono">
                    {alert.dest_ip}:{alert.dest_port || 'Any'}
                  </td>
                  <td className="mono" style={{ color: '#60a5fa' }}>
                    {(alert.ml_confidence * 100).toFixed(1)}%
                  </td>
                  <td>
                    {alert.mitre_technique_id ? (
                      <span className="badge badge-mitre" title={alert.mitre_technique_name}>
                        {alert.mitre_technique_id}
                      </span>
                    ) : (
                      <span style={{ color: 'var(--text-dim)' }}>—</span>
                    )}
                  </td>
                  <td>{getStatusBadge(alert.status)}</td>
                  <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    {new Date(alert.detected_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: '4px' }}>
                      <button
                        className="btn btn-secondary btn-sm"
                        style={{ padding: '3px 6px', fontSize: '0.72rem', display: 'inline-flex', alignItems: 'center' }}
                        title="View SHAP Explanation"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectAlert(alert.id);
                        }}
                      >
                        <Search size={11} style={{ marginRight: '4px' }} />
                        Explain
                      </button>
                      {alert.status === 'new' && (
                        <button
                          className="btn btn-primary btn-sm"
                          style={{ padding: '3px 6px', fontSize: '0.72rem', display: 'inline-flex', alignItems: 'center' }}
                          title="Mark Investigating"
                          onClick={(e) => handleQuickStatus(e, alert.id, 'investigating')}
                        >
                          <Zap size={11} style={{ marginRight: '4px' }} />
                          Triage
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

      {/* Pagination */}
      {pages > 1 && (
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '16px' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Page {page} of {pages}
          </span>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              className="btn btn-secondary btn-sm"
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
            >
              Previous
            </button>
            <button
              className="btn btn-secondary btn-sm"
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
