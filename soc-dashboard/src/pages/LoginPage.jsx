import React, { useState } from 'react';
import { Key, UserPlus, Shield, User, Check, AlertTriangle, ShieldCheck } from 'lucide-react';
import { api } from '../api/client';

export default function LoginPage({ onLoginSuccess }) {
  const [activeMode, setActiveMode] = useState('login'); // 'login' or 'register'
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('admin123');
  const [selectedRole, setSelectedRole] = useState('manager');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    try {
      setLoading(true);
      if (activeMode === 'register') {
        await api.createUser({
          username: username.trim(),
          password: password.trim(),
          role: selectedRole,
        });
        setSuccessMsg(`Profile '${username}' registered [${selectedRole.toUpperCase()}]. Authenticating...`);
        const loggedUser = await api.login(username.trim(), password.trim());
        setTimeout(() => onLoginSuccess(loggedUser), 600);
      } else {
        const user = await api.login(username.trim(), password.trim());
        onLoginSuccess(user);
      }
    } catch (err) {
      setError(err.message || 'Authentication failed. Verify credentials.');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickFill = (u, p, r = 'analyst') => {
    setUsername(u);
    setPassword(p);
    setSelectedRole(r);
    setError(null);
  };

  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '75vh' }}>
      <div className="panel" style={{ maxWidth: '440px', width: '100%', padding: '24px' }}>
        <div style={{ textAlign: 'center', marginBottom: '20px' }}>
          <div className="brand-icon" style={{ margin: '0 auto 10px auto', width: '38px', height: '38px' }}>
            <Shield size={20} />
          </div>
          <h2 style={{ fontFamily: 'var(--font-display)', color: '#fff', fontSize: '16px', fontWeight: 700, letterSpacing: '-0.01em' }}>
            XAI-IDPS-SOC GATEWAY
          </h2>
          <p style={{ fontSize: '11.5px', color: 'var(--text-muted)', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
            OPERATOR AUTHENTICATION & ACCESS CONTROL
          </p>
        </div>

        {/* Mode Selector Tabs */}
        <div style={{ display: 'flex', background: 'var(--bg-inset)', borderRadius: 'var(--radius-xs)', padding: '2px', marginBottom: '16px', border: '1px solid var(--border-hairline)' }}>
          <button
            id="tab-mode-login"
            type="button"
            onClick={() => { setActiveMode('login'); setError(null); }}
            className={`sec-btn sec-btn-sm ${activeMode === 'login' ? 'sec-btn-primary' : 'sec-btn-ghost'}`}
            style={{ flex: 1, borderRadius: 'var(--radius-xs)' }}
          >
            <Key size={12} />
            <span>Sign In</span>
          </button>
          <button
            id="tab-mode-register"
            type="button"
            onClick={() => { setActiveMode('register'); setError(null); }}
            className={`sec-btn sec-btn-sm ${activeMode === 'register' ? 'sec-btn-primary' : 'sec-btn-ghost'}`}
            style={{ flex: 1, borderRadius: 'var(--radius-xs)' }}
          >
            <UserPlus size={12} />
            <span>Provision Profile</span>
          </button>
        </div>

        {error && (
          <div
            style={{
              background: 'var(--signal-crit-bg)',
              border: '1px solid var(--signal-crit-border)',
              color: 'var(--signal-crit)',
              padding: '8px 12px',
              borderRadius: 'var(--radius-xs)',
              fontSize: '11.5px',
              fontFamily: 'var(--font-mono)',
              marginBottom: '14px',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <AlertTriangle size={13} />
            <span>{error}</span>
          </div>
        )}

        {successMsg && (
          <div
            style={{
              background: 'var(--signal-low-bg)',
              border: '1px solid var(--signal-low-border)',
              color: 'var(--signal-low)',
              padding: '8px 12px',
              borderRadius: 'var(--radius-xs)',
              fontSize: '11.5px',
              fontFamily: 'var(--font-mono)',
              marginBottom: '14px',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <Check size={13} />
            <span>{successMsg}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div>
            <label style={{ fontSize: '10.5px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
              Operator Username
            </label>
            <input
              id="input-login-username"
              type="text"
              className="sec-input"
              style={{ width: '100%', fontFamily: 'var(--font-mono)' }}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>

          <div>
            <label style={{ fontSize: '10.5px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
              Access Password
            </label>
            <input
              id="input-login-password"
              type="password"
              className="sec-input"
              style={{ width: '100%', fontFamily: 'var(--font-mono)' }}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>

          {activeMode === 'register' && (
            <div>
              <label style={{ fontSize: '10.5px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
                Assigned RBAC Role
              </label>
              <select
                id="select-register-role"
                className="sec-select"
                style={{ width: '100%', cursor: 'pointer' }}
                value={selectedRole}
                onChange={(e) => setSelectedRole(e.target.value)}
              >
                <option value="admin">Administrator [Full Platform Control]</option>
                <option value="manager">SOC Lead [Incident Management & Review]</option>
                <option value="employee">Internal User [Standard Telemetry]</option>
                <option value="analyst">Security Analyst [Alert Triage & SHAP]</option>
                <option value="viewer">Auditor [Read-Only Telemetry]</option>
              </select>
            </div>
          )}

          <button
            id="btn-login-submit"
            type="submit"
            className="sec-btn sec-btn-primary"
            style={{ width: '100%', marginTop: '6px' }}
            disabled={loading}
          >
            {loading
              ? 'Authenticating...'
              : activeMode === 'register'
              ? 'Provision & Sign In Profile'
              : 'Sign In to Console'}
          </button>
        </form>

        {/* Quick Demo Profiles */}
        <div style={{ marginTop: '18px', paddingTop: '14px', borderTop: '1px solid var(--border-hairline)', textAlign: 'center' }}>
          <span style={{ fontSize: '10.5px', color: 'var(--text-muted)', display: 'block', marginBottom: '8px', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
            Preset Evaluation Profiles:
          </span>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '6px' }}>
            <button
              id="btn-demo-admin"
              type="button"
              className="sec-btn sec-btn-ghost sec-btn-sm"
              onClick={() => handleQuickFill('admin', 'admin123', 'admin')}
            >
              [ADMIN] admin
            </button>
            <button
              id="btn-demo-manager"
              type="button"
              className="sec-btn sec-btn-ghost sec-btn-sm"
              onClick={() => handleQuickFill('manager', 'manager123', 'manager')}
            >
              [LEAD] manager
            </button>
            <button
              id="btn-demo-employee"
              type="button"
              className="sec-btn sec-btn-ghost sec-btn-sm"
              onClick={() => handleQuickFill('employee', 'employee123', 'employee')}
            >
              [USER] employee
            </button>
            <button
              id="btn-demo-analyst"
              type="button"
              className="sec-btn sec-btn-ghost sec-btn-sm"
              onClick={() => handleQuickFill('analyst', 'analyst123', 'analyst')}
            >
              [ANALYST] analyst
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
