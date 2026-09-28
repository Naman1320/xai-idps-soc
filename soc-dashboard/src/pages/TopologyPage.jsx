import React, { useState, useEffect } from 'react';
import { api } from '../api/client';
import {
  Crosshair,
  Radio,
  Shield,
  Globe,
  Lock,
  Database,
  Network,
  Activity,
  AlertTriangle,
  ArrowRight,
  Server,
  Layers,
  Loader2
} from 'lucide-react';

export default function TopologyPage({ onSelectAlert }) {
  const [graphData, setGraphData] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadTopology() {
      try {
        setLoading(true);
        const data = await api.getTopologyGraph();
        setGraphData(data);
        if (data.nodes && data.nodes.length > 0) {
          setSelectedNode(data.nodes[3]); // Default to DMZ Web Server
        }
      } catch (err) {
        console.error('Failed to load topology:', err);
      } finally {
        setLoading(false);
      }
    }
    loadTopology();
  }, []);

  if (loading) {
    return (
      <div className="panel" style={{ padding: '48px', textAlign: 'center' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', color: 'var(--text-muted)', fontSize: '13px', fontFamily: 'var(--font-mono)' }}>
          <Loader2 size={16} className="spin" style={{ color: 'var(--cyan-bright)' }} />
          <span>Rendering digital twin & sensor placement topology...</span>
        </div>
      </div>
    );
  }

  const getNodeColor = (type) => {
    if (type === 'threat') return 'var(--crimson-bright)';
    if (type === 'firewall') return 'var(--cyan-bright)';
    if (type === 'sensor') return 'var(--blue-bright)';
    if (type === 'database') return 'var(--emerald-bright)';
    if (type === 'server') return '#a855f7';
    return 'var(--amber-bright)';
  };

  const getTargetAlerts = (nodeIp) => {
    if (!graphData || !graphData.active_threats) return [];
    return graphData.active_threats.filter((t) => t.dest_ip === nodeIp || t.source_ip === nodeIp);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Topology Header */}
      <div className="panel" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
              <span className="sec-badge sec-badge-neutral" style={{ fontFamily: 'var(--font-mono)' }}>
                DIGITAL TWIN TOPOLOGY
              </span>
              <span className="sec-badge sec-badge-info" style={{ fontFamily: 'var(--font-mono)' }}>
                ZONE: MULTI-TIER DMZ + TAP SENSOR
              </span>
            </div>
            <h3 style={{ color: 'var(--text-primary)', fontSize: '1.15rem', fontWeight: 700, margin: 0 }}>
              Perimeter Defense Architecture & Sensor Placement
            </h3>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '4px 0 0 0' }}>
              Maps ingress attack vectors, SPAN port packet mirror taps, and asset criticality tiers.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '16px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--crimson-bright)' }}>
              <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--crimson-bright)' }}></span>
              Threat Origin
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--cyan-bright)' }}>
              <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--cyan-bright)' }}></span>
              Edge Firewall
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--blue-bright)' }}>
              <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--blue-bright)' }}></span>
              IDPS Sensor TAP
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#c084fc' }}>
              <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#a855f7' }}></span>
              Protected Assets
            </span>
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '20px' }}>
        {/* Visual Network Canvas */}
        <div
          className="panel"
          style={{
            minHeight: '440px',
            background: 'radial-gradient(circle at 40% 50%, rgba(6, 182, 212, 0.03) 0%, var(--surface-base) 80%)',
            position: 'relative',
            overflow: 'hidden',
            padding: 0,
          }}
        >
          {/* Subtle Grid Lines Overlay */}
          <div
            style={{
              position: 'absolute',
              inset: 0,
              backgroundImage: 'linear-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 255, 255, 0.02) 1px, transparent 1px)',
              backgroundSize: '24px 24px',
              pointerEvents: 'none',
            }}
          />

          {/* SVG Connection Lines */}
          <svg style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', zIndex: 1, pointerEvents: 'none' }}>
            <defs>
              <linearGradient id="ingressFlow" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#f43f5e" stopOpacity="0.8" />
                <stop offset="50%" stopColor="#06b6d4" stopOpacity="0.6" />
                <stop offset="100%" stopColor="#8b5cf6" stopOpacity="0.8" />
              </linearGradient>
            </defs>

            {/* Ingress threat stream */}
            <line x1="16%" y1="50%" x2="38%" y2="50%" stroke="var(--crimson-bright)" strokeWidth="2" strokeDasharray="6,4" />
            {/* SPAN mirror to sensor */}
            <line x1="38%" y1="50%" x2="38%" y2="22%" stroke="var(--blue-bright)" strokeWidth="2" strokeDasharray="4,4" />
            {/* Forward to DMZ Web */}
            <line x1="38%" y1="50%" x2="68%" y2="35%" stroke="url(#ingressFlow)" strokeWidth="2" />
            {/* Forward to Bastion */}
            <line x1="38%" y1="50%" x2="68%" y2="65%" stroke="rgba(255,255,255,0.15)" strokeWidth="1.5" />
            {/* Web to Database */}
            <line x1="68%" y1="35%" x2="88%" y2="50%" stroke="var(--emerald-bright)" strokeWidth="2" />
          </svg>

          {/* Render Nodes */}
          <div style={{ position: 'relative', height: '100%', minHeight: '440px', zIndex: 2 }}>
            {/* 1. Attacker Node */}
            <div
              onClick={() => setSelectedNode(graphData.nodes[0])}
              style={{
                position: 'absolute',
                left: '6%',
                top: '40%',
                cursor: 'pointer',
                textAlign: 'center',
                transform: selectedNode?.id === 'ext-attacker' ? 'scale(1.06)' : 'scale(1)',
                transition: 'all 0.15s ease',
              }}
            >
              <div
                style={{
                  width: '52px',
                  height: '52px',
                  borderRadius: '4px',
                  background: 'rgba(244, 63, 94, 0.12)',
                  border: `1px solid ${selectedNode?.id === 'ext-attacker' ? 'var(--crimson-bright)' : 'rgba(244, 63, 94, 0.4)'}`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  margin: '0 auto 6px auto',
                  boxShadow: selectedNode?.id === 'ext-attacker' ? '0 0 16px rgba(244, 63, 94, 0.4)' : 'none',
                }}
              >
                <Crosshair size={22} color="var(--crimson-bright)" />
              </div>
              <strong style={{ fontSize: '11px', color: 'var(--crimson-bright)', display: 'block' }}>Attacker Subnet</strong>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>192.168.10.x</span>
            </div>

            {/* 2. Sensor Node (Tap) */}
            <div
              onClick={() => setSelectedNode(graphData.nodes[2])}
              style={{
                position: 'absolute',
                left: '33%',
                top: '8%',
                cursor: 'pointer',
                textAlign: 'center',
                transform: selectedNode?.id === 'ids-sensor' ? 'scale(1.06)' : 'scale(1)',
                transition: 'all 0.15s ease',
              }}
            >
              <div
                style={{
                  width: '52px',
                  height: '52px',
                  borderRadius: '4px',
                  background: 'rgba(59, 130, 246, 0.12)',
                  border: `1px solid ${selectedNode?.id === 'ids-sensor' ? 'var(--blue-bright)' : 'rgba(59, 130, 246, 0.4)'}`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  margin: '0 auto 6px auto',
                  boxShadow: selectedNode?.id === 'ids-sensor' ? '0 0 16px rgba(59, 130, 246, 0.4)' : 'none',
                }}
              >
                <Radio size={22} color="var(--blue-bright)" />
              </div>
              <strong style={{ fontSize: '11px', color: 'var(--blue-bright)', display: 'block' }}>IDPS Sensor (TAP)</strong>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>CICFlowMeter</span>
            </div>

            {/* 3. Perimeter Firewall */}
            <div
              onClick={() => setSelectedNode(graphData.nodes[1])}
              style={{
                position: 'absolute',
                left: '33%',
                top: '40%',
                cursor: 'pointer',
                textAlign: 'center',
                transform: selectedNode?.id === 'edge-firewall' ? 'scale(1.06)' : 'scale(1)',
                transition: 'all 0.15s ease',
              }}
            >
              <div
                style={{
                  width: '54px',
                  height: '54px',
                  borderRadius: '4px',
                  background: 'rgba(6, 182, 212, 0.12)',
                  border: `1px solid ${selectedNode?.id === 'edge-firewall' ? 'var(--cyan-bright)' : 'rgba(6, 182, 212, 0.4)'}`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  margin: '0 auto 6px auto',
                  boxShadow: selectedNode?.id === 'edge-firewall' ? '0 0 16px rgba(6, 182, 212, 0.4)' : 'none',
                }}
              >
                <Shield size={24} color="var(--cyan-bright)" />
              </div>
              <strong style={{ fontSize: '11px', color: 'var(--text-primary)', display: 'block' }}>Perimeter Gateway</strong>
              <span style={{ fontSize: '10px', color: 'var(--cyan-bright)', fontFamily: 'var(--font-mono)' }}>10.0.0.1</span>
            </div>

            {/* 4. DMZ Web Server */}
            <div
              onClick={() => setSelectedNode(graphData.nodes[3])}
              style={{
                position: 'absolute',
                left: '64%',
                top: '24%',
                cursor: 'pointer',
                textAlign: 'center',
                transform: selectedNode?.id === 'web-dmz' ? 'scale(1.06)' : 'scale(1)',
                transition: 'all 0.15s ease',
              }}
            >
              <div
                style={{
                  width: '52px',
                  height: '52px',
                  borderRadius: '4px',
                  background: 'rgba(168, 85, 247, 0.12)',
                  border: `1px solid ${selectedNode?.id === 'web-dmz' ? '#a855f7' : 'rgba(168, 85, 247, 0.4)'}`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  margin: '0 auto 6px auto',
                  boxShadow: selectedNode?.id === 'web-dmz' ? '0 0 16px rgba(168, 85, 247, 0.4)' : 'none',
                }}
              >
                <Globe size={22} color="#c084fc" />
              </div>
              <strong style={{ fontSize: '11px', color: '#c084fc', display: 'block' }}>Web Host (DMZ)</strong>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>10.0.0.10:80</span>
            </div>

            {/* 5. Bastion Host */}
            <div
              onClick={() => setSelectedNode(graphData.nodes[4])}
              style={{
                position: 'absolute',
                left: '64%',
                top: '58%',
                cursor: 'pointer',
                textAlign: 'center',
                transform: selectedNode?.id === 'bastion-ssh' ? 'scale(1.06)' : 'scale(1)',
                transition: 'all 0.15s ease',
              }}
            >
              <div
                style={{
                  width: '52px',
                  height: '52px',
                  borderRadius: '4px',
                  background: 'rgba(245, 158, 11, 0.12)',
                  border: `1px solid ${selectedNode?.id === 'bastion-ssh' ? 'var(--amber-bright)' : 'rgba(245, 158, 11, 0.4)'}`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  margin: '0 auto 6px auto',
                  boxShadow: selectedNode?.id === 'bastion-ssh' ? '0 0 16px rgba(245, 158, 11, 0.3)' : 'none',
                }}
              >
                <Lock size={22} color="var(--amber-bright)" />
              </div>
              <strong style={{ fontSize: '11px', color: 'var(--amber-bright)', display: 'block' }}>SSH Bastion</strong>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>10.0.0.15:22</span>
            </div>

            {/* 6. Core Database */}
            <div
              onClick={() => setSelectedNode(graphData.nodes[5])}
              style={{
                position: 'absolute',
                left: '84%',
                top: '40%',
                cursor: 'pointer',
                textAlign: 'center',
                transform: selectedNode?.id === 'sql-db' ? 'scale(1.06)' : 'scale(1)',
                transition: 'all 0.15s ease',
              }}
            >
              <div
                style={{
                  width: '52px',
                  height: '52px',
                  borderRadius: '4px',
                  background: 'rgba(16, 185, 129, 0.12)',
                  border: `1px solid ${selectedNode?.id === 'sql-db' ? 'var(--emerald-bright)' : 'rgba(16, 185, 129, 0.4)'}`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  margin: '0 auto 6px auto',
                  boxShadow: selectedNode?.id === 'sql-db' ? '0 0 16px rgba(16, 185, 129, 0.4)' : 'none',
                }}
              >
                <Database size={22} color="var(--emerald-bright)" />
              </div>
              <strong style={{ fontSize: '11px', color: 'var(--emerald-bright)', display: 'block' }}>SQL Data Tier</strong>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>10.0.0.25</span>
            </div>
          </div>
        </div>

        {/* Selected Node Host Telemetry Drawer */}
        <div className="panel" style={{ background: 'var(--surface-sunken)', display: 'flex', flexDirection: 'column' }}>
          {selectedNode ? (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px', paddingBottom: '10px', borderBottom: '1px solid var(--border-hairline)' }}>
                <span
                  style={{
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    backgroundColor: getNodeColor(selectedNode.type),
                  }}
                />
                <h4 style={{ color: 'var(--text-primary)', fontSize: '13px', fontWeight: 700, margin: 0 }}>
                  {selectedNode.label}
                </h4>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px', marginBottom: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid var(--border-hairline)' }}>
                  <span style={{ color: 'var(--text-muted)' }}>IP Address:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan-bright)', fontWeight: 600 }}>{selectedNode.ip}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid var(--border-hairline)' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Network Zone:</span>
                  <span className="sec-badge sec-badge-neutral" style={{ fontSize: '11px' }}>{selectedNode.zone}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid var(--border-hairline)' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Asset Criticality (w₂):</span>
                  <strong style={{ fontFamily: 'var(--font-mono)', color: selectedNode.criticality >= 0.85 ? 'var(--crimson-bright)' : 'var(--amber-bright)' }}>
                    {(selectedNode.criticality * 100).toFixed(0)}%
                  </strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Inspection Tap:</span>
                  <span style={{ color: 'var(--emerald-bright)', fontWeight: 600, fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                    Active (CICFlowMeter)
                  </span>
                </div>
              </div>

              {/* Correlated Threats Targeting this Node */}
              <div>
                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '8px' }}>
                  Correlated Ingress Threats ({getTargetAlerts(selectedNode.ip).length})
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '220px', overflowY: 'auto' }}>
                  {getTargetAlerts(selectedNode.ip).length === 0 ? (
                    <div style={{ fontSize: '12px', color: 'var(--text-muted)', padding: '12px 0' }}>
                      No active ingress threat anomalies detected on this host.
                    </div>
                  ) : (
                    getTargetAlerts(selectedNode.ip).map((t) => (
                      <div
                        key={t.alert_id}
                        onClick={() => onSelectAlert && onSelectAlert(t.alert_id)}
                        style={{
                          background: 'var(--surface-base)',
                          padding: '8px 10px',
                          borderRadius: '4px',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          cursor: 'pointer',
                          border: '1px solid var(--border-hairline)',
                          transition: 'border-color 0.15s ease',
                        }}
                      >
                        <div>
                          <strong style={{ color: 'var(--text-primary)', fontSize: '12px', display: 'block' }}>{t.attack_class}</strong>
                          <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                            Src: {t.source_ip}
                          </div>
                        </div>
                        <span className="sec-badge sec-badge-critical" style={{ fontSize: '10px', fontFamily: 'var(--font-mono)' }}>
                          {(t.risk_score * 100).toFixed(0)} Risk
                        </span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '40px 16px', fontSize: '12px' }}>
              Select any topology node to inspect perimeter attributes and active flow alerts.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
