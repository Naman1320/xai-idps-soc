import React, { useState, useEffect } from 'react';
import { api } from '../api/client';
import {
  SlidersHorizontal,
  Server,
  Users,
  UserPlus,
  Trash2,
  Save,
  Check,
  X,
  Shield,
  Briefcase,
  Laptop,
  Search,
  Eye,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Loader2
} from 'lucide-react';

export default function SettingsPage() {
  const [settingsData, setSettingsData] = useState(null);
  const [w1, setW1] = useState(0.45);
  const [w2, setW2] = useState(0.25);
  const [w3, setW3] = useState(0.15);
  const [w4, setW4] = useState(0.15);
  const [saving, setSaving] = useState(false);
  const [saveFeedback, setSaveFeedback] = useState(null);
  const [loading, setLoading] = useState(true);

  // User Profiles & RBAC State
  const [usersList, setUsersList] = useState([]);
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState('employee');
  const [creatingUser, setCreatingUser] = useState(false);
  const [userFeedbackMsg, setUserFeedbackMsg] = useState(null);

  const fetchUsers = async () => {
    try {
      const data = await api.getUsers();
      setUsersList(data || []);
    } catch (err) {
      console.error('Failed to load users:', err);
    }
  };

  useEffect(() => {
    async function loadSettings() {
      try {
        setLoading(true);
        const [settingsRes, usersRes] = await Promise.allSettled([
          api.getSettings(),
          api.getUsers(),
        ]);

        if (settingsRes.status === 'fulfilled' && settingsRes.value) {
          setSettingsData(settingsRes.value);
          if (settingsRes.value.weights) {
            setW1(settingsRes.value.weights.w1);
            setW2(settingsRes.value.weights.w2);
            setW3(settingsRes.value.weights.w3);
            if (settingsRes.value.weights.w4 !== undefined) {
              setW4(settingsRes.value.weights.w4);
            }
          }
        }

        if (usersRes.status === 'fulfilled') {
          setUsersList(usersRes.value || []);
        }
      } catch (err) {
        console.error('Failed to load settings:', err);
      } finally {
        setLoading(false);
      }
    }
    loadSettings();
  }, []);

  const getRoleMeta = (role) => {
    const r = (role || 'viewer').toLowerCase();
    if (r === 'admin') return { label: 'Administrator', icon: Shield, badgeClass: 'sec-badge-critical' };
    if (r === 'manager') return { label: 'SOC Manager / Lead', icon: Briefcase, badgeClass: 'sec-badge-low' };
    if (r === 'employee') return { label: 'Corporate Employee', icon: Laptop, badgeClass: 'sec-badge-info' };
    if (r === 'analyst') return { label: 'Security Analyst', icon: Search, badgeClass: 'sec-badge-high' };
    return { label: 'Read-Only Viewer', icon: Eye, badgeClass: 'sec-badge-neutral' };
  };

  const handleCreateProfile = async (e) => {
    e.preventDefault();
    if (!newUsername.trim() || !newPassword.trim()) {
      setUserFeedbackMsg({ type: 'error', text: 'Username and password are required.' });
      return;
    }

    try {
      setCreatingUser(true);
      setUserFeedbackMsg(null);
      const created = await api.createUser({
        username: newUsername.trim(),
        password: newPassword.trim(),
        role: newRole,
      });

      setUserFeedbackMsg({
        type: 'success',
        text: `Provisioned identity profile '${created.username}' with role '${created.role}'.`,
      });
      setNewUsername('');
      setNewPassword('');
      await fetchUsers();
      setTimeout(() => setUserFeedbackMsg(null), 5000);
    } catch (err) {
      setUserFeedbackMsg({
        type: 'error',
        text: 'Failed to provision profile: ' + (err.message || 'Unknown system error'),
      });
    } finally {
      setCreatingUser(false);
    }
  };

  const handleDeleteUser = async (userId, username) => {
    if (!window.confirm(`Revoke authentication and remove profile '${username}'?`)) return;
    try {
      await api.deleteUser(userId);
      setUserFeedbackMsg({ type: 'success', text: `Profile '${username}' removed.` });
      await fetchUsers();
      setTimeout(() => setUserFeedbackMsg(null), 4000);
    } catch (err) {
      setUserFeedbackMsg({ type: 'error', text: 'Error revoking profile: ' + err.message });
    }
  };

  const totalWeight = Math.round((w1 + w2 + w3 + w4) * 100) / 100;
  const isWeightValid = Math.abs(totalWeight - 1.0) <= 0.05;

  const handleSaveWeights = async (e) => {
    e.preventDefault();
    if (!isWeightValid) {
      setSaveFeedback({
        type: 'error',
        text: `Formula constraint violation: Weights must sum to 1.00 (Current: ${totalWeight.toFixed(2)})`,
      });
      return;
    }

    try {
      setSaving(true);
      await api.updateWeights({ w1, w2, w3, w4 });
      setSaveFeedback({
        type: 'success',
        text: 'Composite risk scoring parameters updated and synchronized.',
      });
      setTimeout(() => setSaveFeedback(null), 4000);
    } catch (err) {
      setSaveFeedback({
        type: 'error',
        text: 'Failed to update scoring formula: ' + err.message,
      });
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="panel" style={{ padding: '48px', textAlign: 'center' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', color: 'var(--text-muted)', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>
          <Loader2 size={16} className="spin" style={{ color: 'var(--cyan-bright)' }} />
          <span>Synchronizing platform configuration & asset catalog...</span>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Risk Calibration Controls */}
      <div className="panel">
        <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <SlidersHorizontal size={15} style={{ color: 'var(--cyan-bright)' }} />
              <span className="panel-title">COMPOSITE RISK SCORING CALIBRATION</span>
            </div>
            <div className="panel-subtitle" style={{ marginTop: '2px' }}>
              Deterministic scoring formula: Risk = w₁·ML + w₂·Asset + w₃·ATT&CK + w₄·Threat-Intel
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span
              className={`sec-badge ${isWeightValid ? 'sec-badge-info' : 'sec-badge-critical'}`}
              style={{ fontFamily: 'var(--font-mono)', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
            >
              Sum: {totalWeight.toFixed(2)} / 1.00
              {isWeightValid ? <Check size={12} /> : <X size={12} />}
            </span>
          </div>
        </div>

        {saveFeedback && (
          <div
            style={{
              padding: '10px 14px',
              borderRadius: '4px',
              fontSize: '12px',
              fontFamily: 'var(--font-mono)',
              marginBottom: '16px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              background: saveFeedback.type === 'error' ? 'rgba(244, 63, 94, 0.1)' : 'rgba(16, 185, 129, 0.1)',
              border: `1px solid ${saveFeedback.type === 'error' ? 'var(--crimson-bright)' : 'var(--emerald-bright)'}`,
              color: saveFeedback.type === 'error' ? 'var(--crimson-bright)' : 'var(--emerald-bright)',
            }}
          >
            {saveFeedback.type === 'error' ? <AlertTriangle size={14} /> : <CheckCircle2 size={14} />}
            <span>{saveFeedback.text}</span>
          </div>
        )}

        <form onSubmit={handleSaveWeights}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px', marginBottom: '16px' }}>
            {/* Weight 1: ML Confidence */}
            <div style={{ background: 'var(--surface-sunken)', border: '1px solid var(--border-hairline)', padding: '14px', borderRadius: '4px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>w₁: ML Probability</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan-bright)', fontWeight: 700, fontSize: '13px' }}>
                  {(w1 * 100).toFixed(0)}%
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '10px', height: '28px', lineHeight: 1.3 }}>
                TreeExplainer class probability score from RF / XGBoost
              </div>
              <input
                type="range"
                min="0"
                max="1"
                step="0.05"
                value={w1}
                onChange={(e) => setW1(parseFloat(e.target.value))}
                style={{ width: '100%', accentColor: 'var(--cyan-bright)' }}
              />
            </div>

            {/* Weight 2: Asset Criticality */}
            <div style={{ background: 'var(--surface-sunken)', border: '1px solid var(--border-hairline)', padding: '14px', borderRadius: '4px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>w₂: Asset Criticality</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--amber-bright)', fontWeight: 700, fontSize: '13px' }}>
                  {(w2 * 100).toFixed(0)}%
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '10px', height: '28px', lineHeight: 1.3 }}>
                Context rating of destination host from network inventory
              </div>
              <input
                type="range"
                min="0"
                max="1"
                step="0.05"
                value={w2}
                onChange={(e) => setW2(parseFloat(e.target.value))}
                style={{ width: '100%', accentColor: 'var(--amber-bright)' }}
              />
            </div>

            {/* Weight 3: ATT&CK Severity */}
            <div style={{ background: 'var(--surface-sunken)', border: '1px solid var(--border-hairline)', padding: '14px', borderRadius: '4px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>w₃: ATT&CK Severity</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: '#c084fc', fontWeight: 700, fontSize: '13px' }}>
                  {(w3 * 100).toFixed(0)}%
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '10px', height: '28px', lineHeight: 1.3 }}>
                Inherent impact mapped from Enterprise ATT&CK matrix
              </div>
              <input
                type="range"
                min="0"
                max="1"
                step="0.05"
                value={w3}
                onChange={(e) => setW3(parseFloat(e.target.value))}
                style={{ width: '100%', accentColor: '#a855f7' }}
              />
            </div>

            {/* Weight 4: Threat Intelligence */}
            <div style={{ background: 'var(--surface-sunken)', border: '1px solid var(--border-hairline)', padding: '14px', borderRadius: '4px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>w₄: Threat Intel</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--crimson-bright)', fontWeight: 700, fontSize: '13px' }}>
                  {(w4 * 100).toFixed(0)}%
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '10px', height: '28px', lineHeight: 1.3 }}>
                Source IP reputation score from integrated feeds
              </div>
              <input
                type="range"
                min="0"
                max="1"
                step="0.05"
                value={w4}
                onChange={(e) => setW4(parseFloat(e.target.value))}
                style={{ width: '100%', accentColor: 'var(--crimson-bright)' }}
              />
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <button
              type="submit"
              className="sec-btn sec-btn-primary"
              disabled={saving || !isWeightValid}
              style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
            >
              {saving ? <Loader2 size={13} className="spin" /> : <Save size={13} />}
              <span>{saving ? 'Synchronizing Formula...' : 'Apply Scoring Parameters'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Asset Inventory Table */}
      <div className="panel">
        <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Server size={15} style={{ color: 'var(--cyan-bright)' }} />
              <span className="panel-title">NETWORK ASSET INVENTORY & CRITICALITY MAPPINGS</span>
            </div>
            <div className="panel-subtitle" style={{ marginTop: '2px' }}>
              Destination IP context catalog used for automated asset prioritization (w₂)
            </div>
          </div>
          <span className="sec-badge sec-badge-neutral" style={{ fontFamily: 'var(--font-mono)' }}>
            Static Catalog (YAML Sync)
          </span>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="sec-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Hostname</th>
                <th>Role</th>
                <th>Criticality Rating</th>
                <th>Operating System</th>
                <th>Environment</th>
              </tr>
            </thead>
            <tbody>
              {settingsData?.assets?.map((asset) => {
                const critColor = asset.criticality >= 0.85 ? 'var(--crimson-bright)' : (asset.criticality >= 0.70 ? 'var(--amber-bright)' : 'var(--emerald-bright)');
                return (
                  <tr key={asset.ip}>
                    <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan-bright)', fontWeight: 600 }}>
                      {asset.ip}
                    </td>
                    <td>
                      <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{asset.hostname}</span>
                    </td>
                    <td style={{ color: 'var(--text-muted)' }}>{asset.role}</td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontFamily: 'var(--font-mono)', color: critColor, fontWeight: 700, minWidth: '36px' }}>
                          {(asset.criticality * 100).toFixed(0)}%
                        </span>
                        <div style={{ width: '60px', height: '4px', backgroundColor: 'rgba(255, 255, 255, 0.08)', borderRadius: '2px', overflow: 'hidden' }}>
                          <div style={{ width: `${asset.criticality * 100}%`, height: '100%', backgroundColor: critColor }} />
                        </div>
                      </div>
                    </td>
                    <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{asset.os || 'Linux'}</td>
                    <td>
                      <span className="sec-badge sec-badge-neutral" style={{ fontSize: '11px' }}>
                        {asset.environment || 'Production'}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* User Profiles & RBAC Management Section */}
      <div className="panel" id="user-profiles-section">
        <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Users size={15} style={{ color: 'var(--cyan-bright)' }} />
              <span className="panel-title">ROLE-BASED ACCESS CONTROL (RBAC)</span>
            </div>
            <div className="panel-subtitle" style={{ marginTop: '2px' }}>
              Manage access tiers: Administrator, SOC Lead, Analyst, Corporate Employee, and Auditor
            </div>
          </div>
          <span className="sec-badge sec-badge-info" style={{ fontFamily: 'var(--font-mono)' }}>
            {usersList.length} Active Profiles
          </span>
        </div>

        {userFeedbackMsg && (
          <div
            style={{
              padding: '10px 14px',
              borderRadius: '4px',
              fontSize: '12px',
              fontFamily: 'var(--font-mono)',
              marginBottom: '16px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              background: userFeedbackMsg.type === 'error' ? 'rgba(244, 63, 94, 0.1)' : 'rgba(16, 185, 129, 0.1)',
              border: `1px solid ${userFeedbackMsg.type === 'error' ? 'var(--crimson-bright)' : 'var(--emerald-bright)'}`,
              color: userFeedbackMsg.type === 'error' ? 'var(--crimson-bright)' : 'var(--emerald-bright)',
            }}
          >
            {userFeedbackMsg.type === 'error' ? <XCircle size={14} /> : <CheckCircle2 size={14} />}
            <span>{userFeedbackMsg.text}</span>
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: '20px' }}>
          {/* Existing Profiles Table */}
          <div>
            <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '8px' }}>
              Configured Identity Profiles
            </div>
            <div style={{ border: '1px solid var(--border-hairline)', borderRadius: '4px', overflow: 'hidden' }}>
              <table className="sec-table">
                <thead>
                  <tr>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Created</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {usersList.map((u) => {
                    const meta = getRoleMeta(u.role);
                    const RoleIcon = meta.icon;
                    return (
                      <tr key={u.id}>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <RoleIcon size={14} style={{ color: 'var(--text-muted)' }} />
                            <strong style={{ color: 'var(--text-primary)', fontSize: '12px' }}>{u.username}</strong>
                          </div>
                        </td>
                        <td>
                          <span className={`sec-badge ${meta.badgeClass}`} style={{ fontSize: '11px' }}>
                            {meta.label}
                          </span>
                        </td>
                        <td style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                          {u.created_at ? new Date(u.created_at).toLocaleDateString() : 'System Seed'}
                        </td>
                        <td>
                          {u.username === 'admin' ? (
                            <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontStyle: 'italic' }}>
                              Primary Root
                            </span>
                          ) : (
                            <button
                              className="sec-btn sec-btn-outline sec-btn-sm"
                              style={{ padding: '2px 8px', fontSize: '11px', color: 'var(--crimson-bright)', borderColor: 'rgba(244,63,94,0.3)', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                              onClick={() => handleDeleteUser(u.id, u.username)}
                              title="Delete Profile"
                            >
                              <Trash2 size={11} />
                              <span>Revoke</span>
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Add New Profile Card */}
          <div style={{ background: 'var(--surface-sunken)', border: '1px solid var(--border-hairline)', borderRadius: '4px', padding: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
              <UserPlus size={14} style={{ color: 'var(--cyan-bright)' }} />
              <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Provision Access Profile
              </div>
            </div>
            <p style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '14px' }}>
              Authorize a new identity with scoped platform permissions.
            </p>

            <form onSubmit={handleCreateProfile}>
              <div style={{ marginBottom: '12px' }}>
                <label style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
                  USERNAME
                </label>
                <input
                  id="input-new-profile-username"
                  type="text"
                  className="sec-input"
                  style={{ width: '100%' }}
                  placeholder="e.g. sec_manager, jane_doe"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  required
                />
              </div>

              <div style={{ marginBottom: '12px' }}>
                <label style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
                  PASSWORD
                </label>
                <input
                  id="input-new-profile-password"
                  type="password"
                  className="sec-input"
                  style={{ width: '100%' }}
                  placeholder="••••••••"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                />
              </div>

              <div style={{ marginBottom: '16px' }}>
                <label style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
                  ROLE ASSIGNMENT
                </label>
                <select
                  id="select-new-profile-role"
                  className="sec-input"
                  style={{ width: '100%', cursor: 'pointer' }}
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value)}
                >
                  <option value="admin">Administrator (Full System & Config Control)</option>
                  <option value="manager">Manager (SOC Lead, Incident Triage & Approvals)</option>
                  <option value="employee">Employee (Corporate User Telemetry)</option>
                  <option value="analyst">Analyst (Triage, Forensics & SHAP Attribution)</option>
                  <option value="viewer">Viewer (Read-Only Observation)</option>
                </select>
              </div>

              <button
                id="btn-create-profile-submit"
                type="submit"
                className="sec-btn sec-btn-primary"
                style={{ width: '100%', padding: '8px 14px', fontSize: '12px', display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '6px' }}
                disabled={creatingUser}
              >
                {creatingUser ? <Loader2 size={13} className="spin" /> : <UserPlus size={13} />}
                <span>{creatingUser ? 'Provisioning Profile...' : 'Provision Access Profile'}</span>
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
