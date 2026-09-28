import React from 'react';

export default function MitreCard({ mitreId, mitreName, tactic, severity, description }) {
  if (!mitreId) {
    return (
      <div className="card" style={{ padding: '16px', color: 'var(--text-muted)' }}>
        <p>No MITRE ATT&CK technique mapped for this alert class.</p>
      </div>
    );
  }

  const mitreUrl = `https://attack.mitre.org/techniques/${mitreId.replace('.', '/')}/`;

  const getSevClass = (s) => {
    const lower = (s || '').toLowerCase();
    if (lower === 'critical') return 'badge-critical';
    if (lower === 'high') return 'badge-high';
    if (lower === 'medium') return 'badge-medium';
    return 'badge-low';
  };

  return (
    <div className="panel">
      <div className="panel-header" style={{ marginBottom: '0' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span className="sec-badge sec-badge-mitre">{mitreId}</span>
          <span style={{ color: '#fff', fontSize: '13px', fontWeight: 600 }}>{mitreName}</span>
        </div>
        <span className={`sec-badge ${getSevClass(severity)}`}>{severity || 'Medium'}</span>
      </div>

      <div className="panel-body">

      <div style={{ display: 'flex', gap: '20px', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '10px' }}>
        <div>
          <span style={{ color: 'var(--text-muted)' }}>Tactic: </span>
          <strong style={{ color: '#c084fc' }}>{tactic || 'General'}</strong>
        </div>
        <div>
          <span style={{ color: 'var(--text-muted)' }}>Framework: </span>
          <strong style={{ color: '#e2e8f0' }}>Enterprise ATT&CK v15</strong>
        </div>
      </div>

      {description && (
        <p style={{ fontSize: '0.82rem', color: '#cbd5e1', lineHeight: 1.5, marginBottom: '12px' }}>
          {description}
        </p>
      )}

      <a
        href={mitreUrl}
        target="_blank"
        rel="noopener noreferrer"
        style={{
          fontSize: '0.78rem',
          color: 'var(--cyan-bright)',
          textDecoration: 'none',
          display: 'inline-flex',
          alignItems: 'center',
          gap: '4px',
          fontWeight: 600,
        }}
      >
        View Technique on attack.mitre.org ↗
      </a>
      </div>
    </div>
  );
}
