import React from 'react';
import { Activity, Shield } from 'lucide-react';

/**
 * SHAP Waterfall Chart Component.
 * Local feature attribution visualization showing how individual network flow features pushed
 * the tree classifier's prediction from the baseline value toward the final attack probability.
 */
export default function ShapWaterfall({ explanation, mlConfidence, attackClass }) {
  if (!explanation || !explanation.features || explanation.features.length === 0) {
    return (
      <div className="panel" style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)' }}>
        <p style={{ fontSize: '12px' }}>No SHAP local explainability attributions recorded for this flow.</p>
      </div>
    );
  }

  const features = explanation.features;
  const maxAbsShap = Math.max(...features.map((f) => Math.abs(f.shap_value)), 0.1);
  const baseValue = explanation.base_value || 0.10;

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title">
          <Activity size={14} />
          <span>SHAP TreeExplainer Local Attribution Matrix</span>
        </div>
        <div style={{ display: 'flex', gap: '12px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--signal-crit)' }}>
            <span style={{ width: '6px', height: '6px', background: 'var(--signal-crit)', borderRadius: '1px' }}></span>
            + Push Attack
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--signal-low)' }}>
            <span style={{ width: '6px', height: '6px', background: 'var(--signal-low)', borderRadius: '1px' }}></span>
            - Push Benign
          </span>
        </div>
      </div>

      <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
          Base Value: <strong style={{ color: '#fff' }}>{baseValue.toFixed(2)}</strong> → Final Output:{' '}
          <strong style={{ color: 'var(--cyan-bright)' }}>{mlConfidence?.toFixed(2)}</strong>
        </div>

        {features.map((item, idx) => {
          const isPos = item.shap_value >= 0;
          const barWidthPct = Math.min(100, Math.round((Math.abs(item.shap_value) / maxAbsShap) * 48));

          return (
            <div key={item.id || idx} className="waterfall-row">
              <div style={{ minWidth: 0 }}>
                <div className="waterfall-feature-name" title={item.feature_name}>
                  {item.feature_name}
                </div>
                <div className="waterfall-feature-val">
                  Observed: {item.feature_value !== null ? item.feature_value.toLocaleString() : 'N/A'}
                </div>
              </div>

              {/* Bar track centered at 50% */}
              <div className="waterfall-bar-track">
                <div className="waterfall-center-line"></div>
                <div
                  className={`waterfall-bar ${isPos ? 'positive' : 'negative'}`}
                  style={{
                    width: `${barWidthPct}%`,
                  }}
                ></div>
              </div>

              <div className={`waterfall-shap-val ${isPos ? 'pos' : 'neg'}`}>
                {isPos ? `+${item.shap_value.toFixed(3)}` : item.shap_value.toFixed(3)}
              </div>
            </div>
          );
        })}

        {/* Analyst Narrative Box */}
        {explanation.plain_language && (
          <div className="narrative-box" style={{ marginTop: '8px' }}>
            <div className="narrative-title">
              <Shield size={13} style={{ color: 'var(--cyan-bright)' }} />
              <span>Classifier Prediction Rationale</span>
            </div>
            <p className="narrative-text">{explanation.plain_language.summary}</p>
            {explanation.plain_language.recommended_action && (
              <div style={{ marginTop: '8px', paddingTop: '8px', borderTop: '1px solid var(--border-hairline)' }}>
                <span style={{ fontSize: '10.5px', fontWeight: 600, color: 'var(--cyan-bright)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
                  Recommended Containment Action:{' '}
                </span>
                <span style={{ fontSize: '12px', color: 'var(--text-primary)' }}>
                  {explanation.plain_language.recommended_action}
                </span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
