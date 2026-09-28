import React, { useState, useEffect } from 'react';
import { Folder, Plus, X, Save, CheckCircle, AlertTriangle, FileText } from 'lucide-react';
import { api } from '../api/client';

export default function CaseManager({ onSelectAlert }) {
  const [cases, setCases] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedCase, setSelectedCase] = useState(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [statusFeedback, setStatusFeedback] = useState(null);

  // Form states for new case
  const [newTitle, setNewTitle] = useState('');
  const [newSeverity, setNewSeverity] = useState('high');
  const [newNotes, setNewNotes] = useState('');
  const [creating, setCreating] = useState(false);

  // Form states for editing selected case
  const [editStatus, setEditStatus] = useState('open');
  const [editDisposition, setEditDisposition] = useState('');
  const [editNotes, setEditNotes] = useState('');
  const [updating, setUpdating] = useState(false);

  const loadCases = async () => {
    try {
      setLoading(true);
      const res = await api.getCases();
      setCases(res.cases || []);
    } catch (err) {
      console.error('Failed to load incident dossiers:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCases();
  }, []);

  const handleSelectCase = async (caseId) => {
    try {
      const c = await api.getCase(caseId);
      setSelectedCase(c);
      setEditStatus(c.status);
      setEditDisposition(c.disposition || '');
      setEditNotes(c.notes || '');
      setStatusFeedback(null);
    } catch (err) {
      setStatusFeedback({ type: 'error', text: `Failed to load case: ${err.message}` });
    }
  };

  const handleCreateCase = async (e) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    try {
      setCreating(true);
      await api.createCase({
        title: newTitle,
        severity: newSeverity,
        notes: newNotes,
      });
      setShowCreateModal(false);
      setNewTitle('');
      setNewNotes('');
      await loadCases();
      setStatusFeedback({ type: 'success', text: 'Incident case created successfully.' });
    } catch (err) {
      setStatusFeedback({ type: 'error', text: `Creation failed: ${err.message}` });
    } finally {
      setCreating(false);
    }
  };

  const handleUpdateCase = async () => {
    if (!selectedCase) return;
    try {
      setUpdating(true);
      const updated = await api.updateCase(selectedCase.id, {
        status: editStatus,
        disposition: editDisposition || undefined,
        notes: editNotes,
      });
      setSelectedCase(updated);
      await loadCases();
      setStatusFeedback({ type: 'success', text: 'Dossier updates committed.' });
      setTimeout(() => setStatusFeedback(null), 4000);
    } catch (err) {
      setStatusFeedback({ type: 'error', text: `Update failed: ${err.message}` });
    } finally {
      setUpdating(false);
    }
  };

  const getSevBadge = (s) => {
    const sev = (s || '').toLowerCase();
    if (sev === 'critical') return <span className="sec-badge sec-badge-crit">P1 CRIT</span>;
    if (sev === 'high') return <span className="sec-badge sec-badge-high">P2 HIGH</span>;
    if (sev === 'medium') return <span className="sec-badge sec-badge-med">P3 MED</span>;
    return <span className="sec-badge sec-badge-low">P4 LOW</span>;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      {/* Command Strip */}
      <div className="command-strip">
        <div className="command-strip-left">
          <div className="command-deck-title">
            <Folder size={16} />
            <span>SECURITY INCIDENT & DOSSIER REPOSITORY</span>
            <span className="sec-badge sec-badge-neutral">{cases.length} REGISTERED CASES</span>
          </div>

          <div className="command-status-pills">
            <span className="status-pip active">
              {cases.filter((c) => c.status === 'open' || c.status === 'investigating').length} UNDER INVESTIGATION
            </span>
          </div>
        </div>

        <div className="command-strip-actions">
          <button className="sec-btn sec-btn-primary sec-btn-sm" onClick={() => setShowCreateModal(true)}>
            <Plus size={13} />
            <span>Create Incident Case</span>
          </button>
        </div>
      </div>

      {statusFeedback && (
        <div
          style={{
            padding: '8px 14px',
            borderRadius: 'var(--radius-xs)',
            fontSize: '12px',
            fontFamily: 'var(--font-mono)',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            background: statusFeedback.type === 'error' ? 'var(--signal-crit-bg)' : 'var(--signal-low-bg)',
            border: `1px solid ${statusFeedback.type === 'error' ? 'var(--signal-crit-border)' : 'var(--signal-low-border)'}`,
            color: statusFeedback.type === 'error' ? 'var(--signal-crit)' : 'var(--signal-low)',
          }}
        >
          {statusFeedback.type === 'error' ? <AlertTriangle size={14} /> : <CheckCircle size={14} />}
          <span>{statusFeedback.text}</span>
        </div>
      )}

      {/* Main Layout Split */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedCase ? '1.2fr 1fr' : '1fr', gap: '16px' }}>
        {/* Case List Table */}
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <FileText size={14} />
              <span>Incident Case Register</span>
            </div>
            <span className="panel-badge">CHRONOLOGICAL</span>
          </div>

          <div className="panel-body-flush sec-table-container">
            <table className="sec-table">
              <thead>
                <tr>
                  <th style={{ width: '85px' }}>Severity</th>
                  <th>Dossier Title</th>
                  <th style={{ width: '95px' }}>Status</th>
                  <th style={{ width: '70px' }}>Alerts</th>
                  <th style={{ width: '90px' }}>Owner</th>
                  <th style={{ width: '95px', textAlign: 'right' }}>Updated</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan="6" style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
                      Loading incident dossiers...
                    </td>
                  </tr>
                ) : cases.length === 0 ? (
                  <tr>
                    <td colSpan="6" style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
                      No incident dossiers registered.
                    </td>
                  </tr>
                ) : (
                  cases.map((c) => {
                    const isSelected = selectedCase?.id === c.id;
                    return (
                      <tr
                        key={c.id}
                        className={isSelected ? 'active' : ''}
                        onClick={() => handleSelectCase(c.id)}
                      >
                        <td>{getSevBadge(c.severity)}</td>
                        <td>
                          <strong style={{ color: '#fff', fontSize: '12.5px' }}>{c.title}</strong>
                        </td>
                        <td>
                          <span className="sec-badge sec-badge-neutral">{c.status.toUpperCase()}</span>
                        </td>
                        <td>
                          <span className="mono-time" style={{ color: '#fff' }}>{c.alerts?.length || 0}</span>
                        </td>
                        <td style={{ color: 'var(--text-secondary)', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                          {c.assigned_to || 'analyst'}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <span className="mono-time">
                            {new Date(c.updated_at).toLocaleDateString()}
                          </span>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Selected Case Detail Drawer */}
        {selectedCase && (
          <div className="panel">
            <div className="panel-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                {getSevBadge(selectedCase.severity)}
                <span className="panel-title" style={{ fontSize: '12px' }}>
                  {selectedCase.title}
                </span>
              </div>
              <button className="sec-btn sec-btn-ghost sec-btn-sm" onClick={() => setSelectedCase(null)}>
                <X size={13} />
              </button>
            </div>

            <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                <div>
                  <label style={{ fontSize: '10.5px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
                    Workflow State:
                  </label>
                  <select
                    className="sec-select"
                    style={{ width: '100%', fontSize: '11.5px' }}
                    value={editStatus}
                    onChange={(e) => setEditStatus(e.target.value)}
                  >
                    <option value="open">Open</option>
                    <option value="investigating">Investigating</option>
                    <option value="resolved">Resolved</option>
                    <option value="closed">Closed</option>
                  </select>
                </div>

                <div>
                  <label style={{ fontSize: '10.5px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
                    Operational Disposition:
                  </label>
                  <select
                    className="sec-select"
                    style={{ width: '100%', fontSize: '11.5px' }}
                    value={editDisposition}
                    onChange={(e) => setEditDisposition(e.target.value)}
                  >
                    <option value="">Pending Analysis</option>
                    <option value="true_positive">True Positive (Incident Confirmed)</option>
                    <option value="false_positive">False Positive (Benign Noise)</option>
                    <option value="benign_activity">Authorized Pentest / Audit</option>
                    <option value="undetermined">Undetermined</option>
                  </select>
                </div>
              </div>

              <div>
                <label style={{ fontSize: '10.5px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
                  Remediation & Forensic Notes:
                </label>
                <textarea
                  className="sec-input"
                  style={{ width: '100%', minHeight: '70px', fontSize: '12px' }}
                  value={editNotes}
                  onChange={(e) => setEditNotes(e.target.value)}
                  placeholder="Record mitigation notes, firewall rule IDs, PCAP findings..."
                />
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
                    Linked Ingress Alerts ({selectedCase.alerts?.length || 0})
                  </span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', maxHeight: '140px', overflowY: 'auto' }}>
                  {(!selectedCase.alerts || selectedCase.alerts.length === 0) ? (
                    <div style={{ color: 'var(--text-muted)', fontSize: '11px', padding: '6px 0' }}>
                      No alerts linked directly to this case.
                    </div>
                  ) : (
                    selectedCase.alerts.map((a) => (
                      <div
                        key={a.id}
                        onClick={() => onSelectAlert && onSelectAlert(a.id)}
                        style={{
                          background: 'var(--bg-inset)',
                          padding: '6px 8px',
                          borderRadius: 'var(--radius-xs)',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          cursor: 'pointer',
                          border: '1px solid var(--border-hairline)',
                        }}
                      >
                        <span style={{ color: '#fff', fontWeight: 600, fontSize: '11.5px' }}>{a.attack_class}</span>
                        <span className="mono-ip" style={{ color: 'var(--cyan-bright)', fontSize: '11px' }}>
                          {a.source_ip} → {a.dest_ip}
                        </span>
                        <span className="sec-badge sec-badge-crit" style={{ fontSize: '9.5px' }}>
                          {(a.risk_score * 100).toFixed(0)}%
                        </span>
                      </div>
                    ))
                  )}
                </div>
              </div>

              <button
                className="sec-btn sec-btn-primary"
                onClick={handleUpdateCase}
                disabled={updating}
                style={{ marginTop: '4px' }}
              >
                <Save size={13} />
                <span>{updating ? 'Committing...' : 'Commit Dossier Updates'}</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Create Case Modal */}
      {showCreateModal && (
        <div className="modal-overlay" onClick={() => setShowCreateModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '580px' }}>
            <div className="modal-header">
              <span className="modal-title">REGISTER SECURITY INCIDENT DOSSIER</span>
              <button className="sec-btn sec-btn-ghost sec-btn-sm" onClick={() => setShowCreateModal(false)}>
                <X size={14} />
              </button>
            </div>
            <form onSubmit={handleCreateCase}>
              <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <div>
                  <label style={{ fontSize: '10.5px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
                    Dossier Title
                  </label>
                  <input
                    type="text"
                    className="sec-input"
                    style={{ width: '100%' }}
                    placeholder="e.g. INC-2025: Coordinated Ingress DDoS"
                    value={newTitle}
                    onChange={(e) => setNewTitle(e.target.value)}
                    required
                  />
                </div>

                <div>
                  <label style={{ fontSize: '10.5px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
                    Initial Severity Rating
                  </label>
                  <select
                    className="sec-select"
                    style={{ width: '100%' }}
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value)}
                  >
                    <option value="critical">P1 Critical</option>
                    <option value="high">P2 High</option>
                    <option value="medium">P3 Medium</option>
                    <option value="low">P4 Low</option>
                  </select>
                </div>

                <div>
                  <label style={{ fontSize: '10.5px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
                    Initial Investigation Scope
                  </label>
                  <textarea
                    className="sec-input"
                    style={{ width: '100%', minHeight: '70px' }}
                    placeholder="Document suspected attack vector, affected host ranges, and sensor IDs..."
                    value={newNotes}
                    onChange={(e) => setNewNotes(e.target.value)}
                  />
                </div>
              </div>

              <div className="modal-footer">
                <button type="button" className="sec-btn sec-btn-ghost" onClick={() => setShowCreateModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="sec-btn sec-btn-primary" disabled={creating}>
                  {creating ? 'Creating...' : 'Register Dossier'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
