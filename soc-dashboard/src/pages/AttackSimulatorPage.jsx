import React, { useState } from 'react';
import { Activity, Search, Key, Globe, Cpu, Terminal, Play, Zap, Shield, AlertTriangle } from 'lucide-react';
import { api } from '../api/client';

export default function AttackSimulatorPage({ onSelectAlert, onAlertGenerated }) {
  const [selectedAttack, setSelectedAttack] = useState('DDoS');
  const [intensity, setIntensity] = useState(1.0);
  const [launching, setLaunching] = useState(false);
  const [logs, setLogs] = useState([
    {
      id: 'log-0',
      time: new Date().toLocaleTimeString(),
      text: 'Sensor engine ready. Synthetic traffic generator armed with calibrated CICIDS2017 distributions.',
      type: 'info',
    },
  ]);

  const attackPresets = [
    {
      id: 'DDoS',
      name: 'Volumetric DDoS Attack (T1498)',
      Icon: Activity,
      desc: 'Floods web servers with high-frequency TCP SYN/UDP packets (35,000+ pkts/s).',
      target: 'DMZ Web Server (10.0.0.10:80)',
      targetIp: '10.0.0.10',
      severity: 'Critical',
      shapFeature: 'Flow Packets/s & Fwd Packet Length Mean',
    },
    {
      id: 'PortScan',
      name: 'Stealth SYN Port Scan (T1046)',
      Icon: Search,
      desc: 'Rapid sequential port discovery across 22, 80, 445, 3389 with zero forward payloads.',
      target: 'Core SQL Cluster (10.0.0.25)',
      targetIp: '10.0.0.25',
      severity: 'Medium',
      shapFeature: 'SYN Flag Count (+0.36) & Zero Payload Len',
    },
    {
      id: 'SSH-Patator',
      name: 'SSH Dictionary Brute Force (T1110)',
      Icon: Key,
      desc: 'Automated credential guessing against port 22 from internal rogue subnet.',
      target: 'Bastion Jump Host (10.0.0.15:22)',
      targetIp: '10.0.0.15',
      severity: 'High',
      shapFeature: 'Dst Port 22 (+0.42) & Flow Duration',
    },
    {
      id: 'Web Attack',
      name: 'Web SQL Injection & XSS (T1190)',
      Icon: Globe,
      desc: 'Injects malicious SQL queries and script tags into HTTP parameters.',
      target: 'DMZ Web Server (10.0.0.10:80)',
      targetIp: '10.0.0.10',
      severity: 'High',
      shapFeature: 'Fwd Packet Length Mean (+0.34)',
    },
    {
      id: 'Botnet',
      name: 'C2 Botnet Beaconing (T1071)',
      Icon: Cpu,
      desc: 'Persistent outbound keep-alive telemetry to external command-and-control server.',
      target: 'External C2 Server (198.51.100.22)',
      targetIp: '198.51.100.22',
      severity: 'High',
      shapFeature: 'Long Flow Duration & Port 8080',
    },
  ];

  const handleLaunchAttack = async () => {
    try {
      setLaunching(true);
      const startTime = performance.now();
      addLog(`Initiating synthetic ${selectedAttack} network packet stream (Intensity: ${intensity}x)...`, 'warn');

      const res = await api.triggerSimulatedAttack(selectedAttack, intensity);
      const elapsed = (performance.now() - startTime).toFixed(1);

      addLog(`[Flow Captured] Features extracted via CICFlowMeter simulation.`, 'info');
      addLog(`[ML Inference] Model evaluated flow: ${res.attack_class} (${(res.risk_score * 100).toFixed(0)}% composite risk).`, 'success');
      addLog(`[SHAP Local Attribution] Generated ${res.shap_features_count} feature vectors in ${elapsed}ms.`, 'info');
      addLog(`[SOC Ingestion] Ingested alert ID: ${res.alert_id.substring(0, 13)}... into database.`, 'success');

      if (onAlertGenerated) onAlertGenerated();
    } catch (err) {
      addLog(`Attack simulation failed: ${err.message}`, 'error');
    } finally {
      setLaunching(false);
    }
  };

  const handleLaunchAttackWave = async () => {
    try {
      setLaunching(true);
      addLog(`[STREAM INITIATED] Dispatching coordinated 4-vector attack flow into detection pipeline...`, 'warn');
      const wave = [
        { type: 'DDoS', name: 'Volumetric SYN Flood' },
        { type: 'SSH-Patator', name: 'SSH Credential Brute Force' },
        { type: 'Web Attack', name: 'SQL Injection / XSS Exploit' },
        { type: 'PortScan', name: 'Stealth TCP Port Sweep' },
      ];

      for (let i = 0; i < wave.length; i++) {
        const item = wave[i];
        const t0 = performance.now();
        addLog(`[Vector ${i + 1}/4] Injecting ${item.name} (${item.type})...`, 'warn');
        const res = await api.triggerSimulatedAttack(item.type, intensity);
        const dt = (performance.now() - t0).toFixed(1);
        addLog(`  -> [Classified: ${res.attack_class}] Risk: ${(res.risk_score * 100).toFixed(0)}% | SHAP: ${res.shap_features_count} features in ${dt}ms | ID: ${res.alert_id.substring(0, 8)}`, 'success');
        if (onAlertGenerated) onAlertGenerated();
        await new Promise((r) => setTimeout(r, 200));
      }

      addLog(`[STREAM COMPLETE] All 4 vectors processed and prioritized in SOC queue.`, 'success');
    } catch (err) {
      addLog(`Stream error: ${err.message}`, 'error');
    } finally {
      setLaunching(false);
    }
  };

  const addLog = (text, type = 'info') => {
    setLogs((prev) => [
      {
        id: `log-${Date.now()}-${Math.random()}`,
        time: new Date().toLocaleTimeString(),
        text,
        type,
      },
      ...prev.slice(0, 40),
    ]);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      {/* Command Strip */}
      <div className="command-strip">
        <div className="command-strip-left">
          <div className="command-deck-title">
            <Zap size={16} />
            <span>SYNTHETIC TRAFFIC REPLAY & ATTACK GENERATOR</span>
            <span className="sec-badge sec-badge-crit">HARNESS ARMED</span>
          </div>

          <div className="command-status-pills">
            <span className="status-pip active">TELEMETRY: CICIDS2017 CALIBRATED</span>
            <span className="status-pip active">REAL-TIME SHAP ENGINE</span>
          </div>
        </div>

        <div className="command-strip-actions">
          <button
            id="btn-launch-single-probe"
            className="sec-btn sec-btn-ghost sec-btn-sm"
            onClick={handleLaunchAttack}
            disabled={launching}
          >
            <Play size={12} />
            <span>{launching ? 'Simulating...' : `Inject ${selectedAttack}`}</span>
          </button>
          <button
            id="btn-launch-attack-wave"
            className="sec-btn sec-btn-danger sec-btn-sm"
            onClick={handleLaunchAttackWave}
            disabled={launching}
          >
            <Zap size={13} />
            <span>{launching ? 'Injecting Stream...' : 'Inject 4-Vector Stream'}</span>
          </button>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.45fr 1fr', gap: '16px' }}>
        {/* Preset Selector */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
            Available Attack Vectors (MITRE ATT&CK):
          </div>

          {attackPresets.map((preset) => {
            const isSelected = selectedAttack === preset.id;
            const PresetIcon = preset.Icon;
            return (
              <div
                key={preset.id}
                onClick={() => setSelectedAttack(preset.id)}
                style={{
                  background: isSelected ? 'var(--bg-surface-elevated)' : 'var(--bg-surface)',
                  border: isSelected ? '1px solid var(--cyan-bright)' : '1px solid var(--border-hairline)',
                  borderRadius: 'var(--radius-xs)',
                  padding: '12px 14px',
                  cursor: 'pointer',
                  transition: 'var(--transition-fast)',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <PresetIcon size={15} style={{ color: isSelected ? 'var(--cyan-bright)' : 'var(--text-secondary)' }} />
                    <strong style={{ color: '#fff', fontSize: '13px' }}>{preset.name}</strong>
                  </div>
                  <span className={`sec-badge ${preset.severity === 'Critical' ? 'sec-badge-crit' : 'sec-badge-high'}`}>
                    {preset.severity}
                  </span>
                </div>

                <p style={{ fontSize: '11.5px', color: 'var(--text-secondary)', marginBottom: '8px', lineHeight: 1.4 }}>
                  {preset.desc}
                </p>

                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                  <span style={{ color: 'var(--text-muted)' }}>
                    TARGET: <strong style={{ color: '#fff' }}>{preset.target}</strong>
                  </span>
                  <span style={{ color: 'var(--cyan-bright)' }}>
                    DRIVER: {preset.shapFeature}
                  </span>
                </div>
              </div>
            );
          })}

          {/* Intensity Slider */}
          <div className="panel" style={{ padding: '12px 14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px', fontSize: '11.5px' }}>
              <span style={{ color: '#fff', fontWeight: 600 }}>Traffic Intensity Multiplier</span>
              <span className="mono-time" style={{ color: 'var(--cyan-bright)', fontWeight: 700 }}>{intensity}x</span>
            </div>
            <input
              type="range"
              min="0.5"
              max="2.5"
              step="0.1"
              value={intensity}
              onChange={(e) => setIntensity(parseFloat(e.target.value))}
              style={{ width: '100%', accentColor: 'var(--cyan-bright)' }}
            />
          </div>
        </div>

        {/* Live Simulation Console */}
        <div className="panel" style={{ display: 'flex', flexDirection: 'column' }}>
          <div className="panel-header">
            <div className="panel-title">
              <Terminal size={14} />
              <span>Simulator Output Stream</span>
            </div>
            <button
              className="sec-btn sec-btn-ghost sec-btn-sm"
              style={{ padding: '1px 6px', fontSize: '10.5px' }}
              onClick={() => setLogs([])}
            >
              Clear
            </button>
          </div>

          <div
            className="syntax-block"
            style={{
              flex: 1,
              maxHeight: '440px',
              overflowY: 'auto',
              borderRadius: 0,
              border: 'none',
              background: 'var(--bg-inset)',
            }}
          >
            {logs.map((log) => {
              let color = 'var(--text-secondary)';
              if (log.type === 'warn') color = 'var(--signal-high)';
              if (log.type === 'success') color = 'var(--signal-low)';
              if (log.type === 'error') color = 'var(--signal-crit)';

              return (
                <div key={log.id} style={{ display: 'flex', gap: '8px', lineHeight: 1.5, fontSize: '11px' }}>
                  <span style={{ color: 'var(--text-dim)' }}>[{log.time}]</span>
                  <span style={{ color }}>{log.text}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
