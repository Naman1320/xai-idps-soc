import React, { useState, useEffect } from 'react';
import { api } from '../api/client';

export default function Dashboard({ onNavigateAlerts, onSelectAlert, onNavigateCases }) {
  const [summary, setSummary] = useState(null);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadDashboardData() {
      try {
        setLoading(true);
        const [sumRes, alertsRes] = await Promise.all([
          api.getSummary(),
          api.getAlerts({ limit: 7, sort_by: 'risk_score', order: 'desc' }),
        ]);
        setSummary(sumRes);
        setRecentAlerts(alertsRes.alerts || []);
      } catch (err) {
        console.error('Failed to load dashboard:', err);
      } finally {
        setLoading(false);
      }
    }
    loadDashboardData();
  }, []);

  const getRiskBadge = (score) => {
    const pct = (score * 100).toFixed(0);
    if (score >= 0.75) return <span className="sec-badge sec-badge-crit">[P1 CRIT] {pct}%</span>;
    if (score >= 0.50) return <span className="sec-badge sec-badge-high">[P2 HIGH] {pct}%</span>;
    if (score >= 0.30) return <span className="sec-badge sec-badge-med">[P3 MED] {pct}%</span>;
    return <span className="sec-badge sec-badge-low">[P4 LOW] {pct}%</span>;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      {/* 1. Tactical Command Header (Operational, high-density, no boilerplate) */}
      <div className="command-strip">
        <div className="command-strip-left">
          <div className="command-deck-title">
            <span>PERIMETER THREAT TRIAGE & SURVEILLANCE</span>
            <span className="sec-badge sec-badge-neutral" style={{ letterSpacing: '0.06em' }}>
              ZONE-A // NORTH-CLUSTER
            </span>
          </div>

          <div className="command-status-pills">
            <span className="status-pip active">4 SENSORS STREAMING</span>
            <span className="status-pip active">XAI TREE-EXPLAINER ONLINE</span>
            <span className="status-pip active">0 DROPPED BUFFERS</span>
          </div>
        </div>

        <div className="command-strip-actions">
          <button className="sec-btn sec-btn-primary sec-btn-sm" onClick={onNavigateAlerts}>
            <span>Alert Queue</span>
            <span style={{ opacity: 0.6, fontSize: '10px', fontFamily: 'var(--font-mono)' }}>[Q]</span>
          </button>
          <button className="sec-btn sec-btn-sm" onClick={onNavigateCases}>
            <span>Active Cases</span>
            <span style={{ opacity: 0.6, fontSize: '10px', fontFamily: 'var(--font-mono)' }}>[C]</span>
          </button>
        </div>
      </div>

      {/* 2. Integrated Telemetry Ribbon (Continuous bar with hairline dividers) */}
      <div className="telemetry-ribbon">
        <div className="telemetry-cell">
          <div className="telemetry-label">
            <span>Critical Priority Queue</span>
            <span className="telemetry-badge" style={{ color: 'var(--signal-crit)', background: 'var(--signal-crit-bg)' }}>
              P1 ALARM
            </span>
          </div>
          <div className="telemetry-value-row">
            <span className="telemetry-value" style={{ color: 'var(--signal-crit)' }}>
              {summary?.critical_alerts ?? 0}
            </span>
            <span className="telemetry-unit">flows</span>
          </div>
          <div className="telemetry-subtext">
            <span>Composite risk threshold ≥ 0.70</span>
          </div>
        </div>

        <div className="telemetry-cell">
          <div className="telemetry-label">
            <span>Ingested Flow Telemetry</span>
            <span className="telemetry-badge" style={{ color: 'var(--cyan-bright)', background: 'var(--cyan-subtle)' }}>
              NETFLOW / PCAP
            </span>
          </div>
          <div className="telemetry-value-row">
            <span className="telemetry-value">
              {summary?.total_alerts ? Number(summary.total_alerts).toLocaleString() : '0'}
            </span>
            <span className="telemetry-unit">records</span>
          </div>
          <div className="telemetry-subtext">
            <span>CICIDS2017 & UNSW-NB15 streams</span>
          </div>
        </div>

        <div className="telemetry-cell">
          <div className="telemetry-label">
            <span>Incident Investigation Deck</span>
            <span className="telemetry-badge" style={{ color: 'var(--signal-high)', background: 'var(--signal-high-bg)' }}>
              SOAR ACTIVE
            </span>
          </div>
          <div className="telemetry-value-row">
            <span className="telemetry-value" style={{ color: 'var(--signal-high)' }}>
              {summary?.open_cases ?? 0}
            </span>
            <span className="telemetry-unit">open dossiers</span>
          </div>
          <div className="telemetry-subtext">
            <span>Under forensic inspection</span>
          </div>
        </div>

        <div className="telemetry-cell">
          <div className="telemetry-label">
            <span>Mean Composite Risk Index</span>
            <span className="telemetry-badge" style={{ color: 'var(--signal-low)', background: 'var(--signal-low-bg)' }}>
              CALIBRATED
            </span>
          </div>
          <div className="telemetry-value-row">
            <span className="telemetry-value" style={{ color: 'var(--signal-low)' }}>
              {summary?.average_risk_score ? (summary.average_risk_score * 100).toFixed(1) : '0.0'}
            </span>
            <span className="telemetry-unit">/ 100</span>
          </div>
          <div className="telemetry-subtext">
            <span>w₁·Confidence + w₂·Asset + w₃·ATT&CK</span>
          </div>
        </div>
      </div>

      {/* 3. Tactical Asymmetric Layout: Dominant Live Threat Deck (66%) + Threat Intel Dock (34%) */}
      <div className="tactical-split-66-34">
        {/* Left (Dominant): Priority Threat Stream with high data density */}
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              <span>Live Ingested Threat Triage Stream</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className="panel-badge">TOP RISK RANKED</span>
              <button className="sec-btn sec-btn-ghost sec-btn-sm" onClick={onNavigateAlerts}>
                Full Queue ↗
              </button>
            </div>
          </div>

          <div className="panel-body-flush sec-table-container">
            <table className="sec-table">
              <thead>
                <tr>
                  <th style={{ width: '110px' }}>Priority</th>
                  <th>Vector Class</th>
                  <th>Flow Coordinates (Src → Dst:Port)</th>
                  <th style={{ width: '100px' }}>ML Conf</th>
                  <th style={{ width: '130px' }}>MITRE Tag</th>
                  <th style={{ width: '80px', textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {recentAlerts.length === 0 ? (
                  <tr>
                    <td colSpan="6" style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
                      No active threats in current buffer. Sensor listening...
                    </td>
                  </tr>
                ) : (
                  recentAlerts.map((a) => (
                    <tr key={a.id} onClick={() => onSelectAlert(a.id)}>
                      <td>{getRiskBadge(a.risk_score)}</td>
                      <td>
                        <strong style={{ color: '#fff', letterSpacing: '-0.01em' }}>{a.attack_class}</strong>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <span className="mono-ip">{a.source_ip}</span>
                          <span style={{ color: 'var(--text-muted)' }}>→</span>
                          <span className="mono-ip" style={{ color: 'var(--text-secondary)' }}>
                            {a.dest_ip}:{a.dest_port || 'Any'}
                          </span>
                        </div>
                      </td>
                      <td>
                        <span className="mono-time" style={{ color: 'var(--cyan-bright)' }}>
                          {(a.ml_confidence * 100).toFixed(1)}%
                        </span>
                      </td>
                      <td>
                        {a.mitre_technique_id ? (
                          <span className="sec-badge sec-badge-mitre">{a.mitre_technique_id}</span>
                        ) : (
                          <span style={{ color: 'var(--text-dim)', fontSize: '11px' }}>—</span>
                        )}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          className="sec-btn sec-btn-ghost sec-btn-sm"
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectAlert(a.id);
                          }}
                          style={{ padding: '2px 6px', fontSize: '10.5px' }}
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

        {/* Right (Dock): Threat Intel Matrix & Tactical Distribution */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {/* MITRE ATT&CK Matrix Panel */}
          <div className="panel">
            <div className="panel-header">
              <div className="panel-title">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
                <span>MITRE ATT&CK Framework Coverage</span>
              </div>
              <span className="panel-badge">v15 ENTERPRISE</span>
            </div>

            <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {!summary?.top_mitre_techniques || summary.top_mitre_techniques.length === 0 ? (
                <div style={{ color: 'var(--text-muted)', fontSize: '12px', padding: '12px' }}>
                  No MITRE attributions detected in current window.
                </div>
              ) : (
                summary.top_mitre_techniques.slice(0, 5).map((t) => (
                  <div
                    key={t.technique_id}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '8px 10px',
                      background: 'var(--bg-inset)',
                      border: '1px solid var(--border-hairline)',
                      borderRadius: 'var(--radius-xs)',
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '2px' }}>
                        <span className="sec-badge sec-badge-mitre">{t.technique_id}</span>
                        <span style={{ color: '#fff', fontSize: '12px', fontWeight: 600 }}>{t.technique_name}</span>
                      </div>
                      <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                        TACTIC: {t.tactic.toUpperCase()}
                      </div>
                    </div>

                    <div style={{ textAlign: 'right' }}>
                      <span className="sec-badge sec-badge-crit" style={{ fontSize: '9.5px' }}>
                        {t.severity}
                      </span>
                      <div className="mono-time" style={{ color: '#fff', marginTop: '2px' }}>
                        {t.count} hits
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Engine Calibration & Sensor Status Card */}
          <div className="panel">
            <div className="panel-header">
              <div className="panel-title">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <rect x="2" y="2" width="20" height="8" rx="2" /><rect x="2" y="14" width="20" height="8" rx="2" />
                  <line x1="6" y1="6" x2="6.01" y2="6" /><line x1="6" y1="18" x2="6.01" y2="18" />
                </svg>
                <span>Detection Engine Calibrations</span>
              </div>
              <span className="sec-badge sec-badge-active">ACTIVE</span>
            </div>

            <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', borderBottom: '1px solid var(--border-hairline)', paddingBottom: '6px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Classifiers</span>
                <span style={{ color: '#fff', fontFamily: 'var(--font-mono)' }}>Random Forest + XGBoost</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', borderBottom: '1px solid var(--border-hairline)', paddingBottom: '6px' }}>
                <span style={{ color: 'var(--text-muted)' }}>SHAP TreeExplainer</span>
                <span style={{ color: 'var(--cyan-bright)', fontFamily: 'var(--font-mono)' }}>Real-time Per-Flow</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', borderBottom: '1px solid var(--border-hairline)', paddingBottom: '6px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Auto-Drop Threshold</span>
                <span style={{ color: 'var(--signal-crit)', fontFamily: 'var(--font-mono)' }}>Score ≥ 0.85 (SOAR)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Audit Trail</span>
                <span style={{ color: 'var(--signal-low)', fontFamily: 'var(--font-mono)' }}>Reversible SQLite Log</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
