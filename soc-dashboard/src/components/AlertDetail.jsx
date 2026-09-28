import React, { useState, useEffect } from 'react';
import {
  Globe,
  Shield,
  AlertTriangle,
  AlertCircle,
  Check,
  X,
  HelpCircle,
  Plus,
  Loader2,
  Server,
  Activity,
} from 'lucide-react';
import { api } from '../api/client';
import ShapWaterfall from './ShapWaterfall';
import MitreCard from './MitreCard';
import RiskScoreBar from './RiskScoreBar';

export default function AlertDetail({ alertId, onClose, onStatusUpdated, onCreateCaseWithAlert }) {
  const [alert, setAlert] = useState(null);
  const [explanation, setExplanation] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [feedbackNotes, setFeedbackNotes] = useState('');
  const [submittingFeedback, setSubmittingFeedback] = useState(false);
  const [feedbackSuccess, setFeedbackSuccess] = useState(null);

  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true);
        const [alertData, explanationData] = await Promise.all([
          api.getAlert(alertId),
          api.getAlertExplanation(alertId).catch(() => null),
        ]);
        setAlert(alertData);
        setExplanation(explanationData);
      } catch (err) {
        setError(err.message || 'Failed to load telemetry record');
      } finally {
        setLoading(false);
      }
    }
    if (alertId) {
      loadData();
    }
  }, [alertId]);

  const handleStatusChange = async (newStatus) => {
    try {
      await api.updateAlertStatus(alertId, newStatus);
      setAlert((prev) => ({ ...prev, status: newStatus }));
      if (onStatusUpdated) onStatusUpdated(alertId, newStatus);
    } catch (err) {
      setError(`Failed to update status: ${err.message}`);
    }
  };

  const handleFeedback = async (disposition) => {
    try {
      setSubmittingFeedback(true);
      await api.submitFeedback(alertId, {
        disposition,
        notes: feedbackNotes,
      });
      setFeedbackSuccess(`Analyst ground-truth recorded: ${disposition.toUpperCase()}`);
      setTimeout(() => setFeedbackSuccess(null), 4000);
      if (disposition === 'false_positive') {
        setAlert((prev) => ({ ...prev, status: 'dismissed' }));
        if (onStatusUpdated) onStatusUpdated(alertId, 'dismissed');
      }
    } catch (err) {
      setError(`Failed to record disposition: ${err.message}`);
    } finally {
      setSubmittingFeedback(false);
    }
  };

  if (loading) {
    return (
      <div className="modal-overlay" onClick={onClose}>
        <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ textAlign: 'center', padding: '36px' }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', color: 'var(--cyan-bright)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
            <Loader2 size={16} className="spin" />
            <span>RETRIEVING TELEMETRY & ATTRIBUTIONS...</span>
          </div>
        </div>
      </div>
    );
  }

  if (error || !alert) {
    return (
      <div className="modal-overlay" onClick={onClose}>
        <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--signal-crit)', marginBottom: '10px' }}>
            <AlertTriangle size={18} />
            <h3 style={{ fontSize: '14px', fontWeight: 600 }}>Telemetry Ingestion Error</h3>
          </div>
          <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
            {error || 'Alert record not located in database.'}
          </p>
          <button className="sec-btn sec-btn-ghost" onClick={onClose}>Close</button>
        </div>
      </div>
    );
  }

  const detectedDate = new Date(alert.detected_at).toLocaleString();

  const getReputationBadge = (score, isKnownBad) => {
    if (isKnownBad) {
      return (
        <span className="sec-badge sec-badge-crit">
          KNOWN BAD ({score}/100)
        </span>
      );
    }
    if (score >= 50) {
      return (
        <span className="sec-badge sec-badge-high">
          SUSPICIOUS ({score}/100)
        </span>
      );
    }
    if (score > 0) {
      return (
        <span className="sec-badge sec-badge-med">
          LOW RISK ({score}/100)
        </span>
      );
    }
    return (
      <span className="sec-badge sec-badge-low">
        CLEAN (0/100)
      </span>
    );
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-content"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: '940px', maxHeight: '88vh', overflowY: 'auto' }}
      >
        {/* Modal Header */}
        <div className="modal-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
              <span className="sec-badge sec-badge-crit">{alert.attack_class}</span>
              <span className="sec-badge sec-badge-neutral">STATUS: {alert.status.toUpperCase()}</span>
              <span style={{ color: 'var(--text-muted)', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                ID: {alert.id.substring(0, 16)}...
              </span>
            </div>
            <div style={{ fontSize: '11.5px', color: 'var(--text-secondary)' }}>
              Detected at <span style={{ color: '#fff', fontFamily: 'var(--font-mono)' }}>{detectedDate}</span>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <button
              className="sec-btn sec-btn-primary sec-btn-sm"
              onClick={() => onCreateCaseWithAlert && onCreateCaseWithAlert(alert)}
            >
              <Plus size={13} />
              <span>Create Case Dossier</span>
            </button>
            <button className="sec-btn sec-btn-ghost sec-btn-sm" onClick={onClose}>
              <X size={14} />
            </button>
          </div>
        </div>

        <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Telemetry Summary Strip */}
          <div className="telemetry-ribbon" style={{ marginBottom: 0 }}>
            <div className="telemetry-cell">
              <span className="telemetry-label">Source Coordinates</span>
              <span className="mono-ip" style={{ color: 'var(--cyan-bright)', fontSize: '13px' }}>
                {alert.source_ip}
              </span>
            </div>
            <div className="telemetry-cell">
              <span className="telemetry-label">Destination Port</span>
              <span className="mono-ip" style={{ fontSize: '13px' }}>
                {alert.dest_ip}:{alert.dest_port || 'Any'}
              </span>
            </div>
            <div className="telemetry-cell">
              <span className="telemetry-label">Classifier Confidence</span>
              <span className="telemetry-value" style={{ fontSize: '16px', color: 'var(--signal-low)' }}>
                {(alert.ml_confidence * 100).toFixed(1)}% ({alert.protocol})
              </span>
            </div>
            <div className="telemetry-cell">
              <span className="telemetry-label">Asset Criticality</span>
              <span className="telemetry-value" style={{ fontSize: '16px', color: 'var(--signal-high)' }}>
                {(alert.asset_criticality * 100).toFixed(0)}% Weight
              </span>
            </div>
          </div>

          {/* Two-Column: Risk Score & MITRE */}
          <div className="tactical-split-55-45">
            <RiskScoreBar
              score={alert.risk_score}
              components={alert.risk_score_components}
            />
            <MitreCard
              mitreId={alert.mitre_technique_id}
              mitreName={alert.mitre_technique_name}
              tactic={alert.mitre_tactic}
              severity={alert.mitre_severity}
              description={alert.mitre_description}
            />
          </div>

          {/* Threat Intelligence & Geolocation */}
          {(alert.geo_source_country || alert.threat_intel_score !== null) && (
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <Globe size={14} />
                  <span>Geolocation & External Threat Reputation</span>
                </div>
                {alert.geo_is_synthetic && (
                  <span className="sec-badge sec-badge-med">SYNTHETIC TEST IP</span>
                )}
              </div>

              <div className="panel-body" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>
                {/* Geolocation */}
                <div style={{ background: 'var(--bg-inset)', padding: '10px 12px', borderRadius: 'var(--radius-xs)', border: '1px solid var(--border-hairline)' }}>
                  <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', marginBottom: '4px' }}>
                    Source Geographic Origin
                  </div>
                  {alert.geo_source_country ? (
                    <div style={{ fontSize: '12px', lineHeight: 1.6 }}>
                      <div style={{ color: '#fff', fontWeight: 600 }}>
                        {alert.geo_source_city && `${alert.geo_source_city}, `}
                        {alert.geo_source_region && `${alert.geo_source_region}, `}
                        {alert.geo_source_country}
                        {alert.geo_source_country_code && ` [${alert.geo_source_country_code}]`}
                      </div>
                      {alert.geo_source_asn_org && (
                        <div style={{ color: 'var(--text-secondary)', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                          ASN: {alert.geo_source_asn || '—'} · {alert.geo_source_asn_org}
                        </div>
                      )}
                      {alert.geo_source_lat && (
                        <div style={{ color: 'var(--text-muted)', fontSize: '10.5px', fontFamily: 'var(--font-mono)' }}>
                          COORDS: {alert.geo_source_lat.toFixed(4)}, {alert.geo_source_lon.toFixed(4)}
                        </div>
                      )}
                    </div>
                  ) : (
                    <div style={{ color: 'var(--text-muted)', fontSize: '11.5px' }}>No geolocation metadata available.</div>
                  )}
                </div>

                {/* Threat Intelligence */}
                <div style={{ background: 'var(--bg-inset)', padding: '10px 12px', borderRadius: 'var(--radius-xs)', border: '1px solid var(--border-hairline)' }}>
                  <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', marginBottom: '4px' }}>
                    AbuseIPDB Threat Reputation
                  </div>
                  {alert.threat_intel_score !== null && alert.threat_intel_score !== undefined ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        {getReputationBadge(alert.threat_intel_score, alert.threat_intel_is_known_bad)}
                        {alert.threat_intel_provider && (
                          <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                            FEED: {alert.threat_intel_provider.toUpperCase()}
                          </span>
                        )}
                      </div>
                      {alert.threat_intel_reports > 0 && (
                        <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                          Reported incidents: <strong style={{ color: '#fff', fontFamily: 'var(--font-mono)' }}>{alert.threat_intel_reports}</strong>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div style={{ color: 'var(--text-muted)', fontSize: '11.5px' }}>No threat reputation recorded.</div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* SHAP Waterfall Attribution */}
          <ShapWaterfall
            explanation={explanation}
            mlConfidence={alert.ml_confidence}
            attackClass={alert.attack_class}
          />

          {/* Network Flow Features Table */}
          {alert.flow_features && Object.keys(alert.flow_features).length > 0 && (
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <Activity size={14} />
                  <span>Captured NetFlow Attributes (CICFlowMeter)</span>
                </div>
                <span className="panel-badge">{Object.keys(alert.flow_features).length} FEATURES</span>
              </div>

              <div className="panel-body" style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '6px' }}>
                {Object.entries(alert.flow_features).map(([key, val]) => (
                  <div
                    key={key}
                    style={{
                      background: 'var(--bg-inset)',
                      padding: '5px 8px',
                      borderRadius: 'var(--radius-xs)',
                      border: '1px solid var(--border-hairline)',
                      fontSize: '11px',
                    }}
                  >
                    <span style={{ color: 'var(--text-muted)' }}>{key}: </span>
                    <strong style={{ color: '#fff', fontFamily: 'var(--font-mono)' }}>
                      {typeof val === 'number' ? val.toLocaleString() : String(val)}
                    </strong>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Analyst Disposition Module */}
          <div className="panel" style={{ border: '1px solid var(--border-subtle)' }}>
            <div className="panel-header">
              <div className="panel-title">
                <Shield size={14} />
                <span>Analyst Ground-Truth Disposition & Feedback Loop</span>
              </div>
              <span className="panel-badge">CALIBRATION PIPELINE</span>
            </div>

            <div className="panel-body">
              {feedbackSuccess && (
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    background: 'var(--signal-low-bg)',
                    border: '1px solid var(--signal-low-border)',
                    color: 'var(--signal-low)',
                    padding: '8px 12px',
                    borderRadius: 'var(--radius-xs)',
                    fontSize: '12px',
                    marginBottom: '10px',
                    fontFamily: 'var(--font-mono)',
                  }}
                >
                  <Check size={14} />
                  <span>{feedbackSuccess}</span>
                </div>
              )}

              <div style={{ marginBottom: '10px' }}>
                <textarea
                  className="sec-input"
                  style={{ width: '100%', minHeight: '50px', resize: 'vertical' }}
                  placeholder="Record investigation findings (e.g. Validated legitimate stress-test from internal CI pipeline)..."
                  value={feedbackNotes}
                  onChange={(e) => setFeedbackNotes(e.target.value)}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    className="sec-btn sec-btn-primary sec-btn-sm"
                    onClick={() => handleFeedback('true_positive')}
                    disabled={submittingFeedback}
                  >
                    <Check size={13} />
                    <span>True Positive</span>
                  </button>
                  <button
                    className="sec-btn sec-btn-danger sec-btn-sm"
                    onClick={() => handleFeedback('false_positive')}
                    disabled={submittingFeedback}
                  >
                    <X size={13} />
                    <span>False Positive (Dismiss)</span>
                  </button>
                  <button
                    className="sec-btn sec-btn-ghost sec-btn-sm"
                    onClick={() => handleFeedback('unknown')}
                    disabled={submittingFeedback}
                  >
                    <HelpCircle size={13} />
                    <span>Inconclusive</span>
                  </button>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Status:</span>
                  <select
                    className="sec-select"
                    value={alert.status}
                    onChange={(e) => handleStatusChange(e.target.value)}
                    style={{ padding: '3px 8px', fontSize: '11px' }}
                  >
                    <option value="new">New</option>
                    <option value="investigating">Investigating</option>
                    <option value="resolved">Resolved</option>
                    <option value="dismissed">Dismissed</option>
                    <option value="closed">Closed</option>
                  </select>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
