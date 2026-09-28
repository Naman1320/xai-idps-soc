import React, { useState, useEffect } from 'react';
import { AlertTriangle, CheckCircle, Loader2, X, ArrowRight } from 'lucide-react';
import Navbar from './components/Navbar';
import AlertQueue from './components/AlertQueue';
import AlertDetail from './components/AlertDetail';
import CaseManager from './components/CaseManager';
import AnalyticsDashboard from './components/AnalyticsDashboard';
import Dashboard from './pages/Dashboard';
import SettingsPage from './pages/SettingsPage';
import TopologyPage from './pages/TopologyPage';
import AttackSimulatorPage from './pages/AttackSimulatorPage';
import PreventionPage from './pages/PreventionPage';
import CopilotPage from './pages/CopilotPage';
import VivaReportPage from './pages/VivaReportPage';
import GeoMapPage from './pages/GeoMapPage';
import VerificationSuitePage from './pages/VerificationSuitePage';
import LoginPage from './pages/LoginPage';
import { api } from './api/client';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedAlertId, setSelectedAlertId] = useState(null);
  const [currentUser, setCurrentUser] = useState(null);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  useEffect(() => {
    const user = api.getCurrentUser();
    if (user) {
      setCurrentUser(user);
    }
  }, []);

  const handleLogout = () => {
    api.logout();
    setCurrentUser(null);
  };

  const handleLoginSuccess = (user) => {
    setCurrentUser(user);
    setActiveTab('dashboard');
  };

  const handleAlertStatusUpdated = () => {
    setRefreshTrigger((prev) => prev + 1);
  };

  const handleCreateCaseWithAlert = () => {
    setSelectedAlertId(null);
    setActiveTab('cases');
  };

  const [isWaveFiring, setIsWaveFiring] = useState(false);
  const [waveToast, setWaveToast] = useState(null);

  const handleFireAttackWave = async () => {
    try {
      setIsWaveFiring(true);
      setWaveToast({
        type: 'info',
        message: 'Injecting coordinated 4-vector attack flow into telemetry pipeline...',
      });

      const waveVectors = ['DDoS', 'SSH-Patator', 'Web Attack', 'PortScan'];
      const results = [];

      for (const attackType of waveVectors) {
        const res = await api.triggerSimulatedAttack(attackType, 1.25);
        results.push(res);
        setRefreshTrigger((prev) => prev + 1);
        await new Promise((resolve) => setTimeout(resolve, 150));
      }

      setWaveToast({
        type: 'success',
        message: `Simulation stream processed: 4 vectors dispatched (${results.map((r) => r.attack_class).join(', ')}). SHAP attributions generated.`,
      });

      setTimeout(() => {
        setWaveToast(null);
      }, 7000);
    } catch (err) {
      setWaveToast({
        type: 'error',
        message: `Simulation injection failure: ${err.message || 'Pipeline communication error'}`,
      });
      setTimeout(() => setWaveToast(null), 6000);
    } finally {
      setIsWaveFiring(false);
    }
  };

  return (
    <div className="app-container">
      <div className="main-content">
        <Navbar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          currentUser={currentUser}
          onLogout={handleLogout}
          onQuickSimulate={handleFireAttackWave}
          isWaveFiring={isWaveFiring}
        />

        {/* Global Operational Notification Banner */}
        {waveToast && (
          <div
            id="attack-wave-toast-banner"
            style={{
              margin: '12px 24px 0 24px',
              padding: '10px 16px',
              borderRadius: 'var(--radius-sm)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              backgroundColor:
                waveToast.type === 'error'
                  ? 'var(--signal-crit-bg)'
                  : waveToast.type === 'info'
                  ? 'var(--cyan-subtle)'
                  : 'var(--signal-low-bg)',
              border: `1px solid ${
                waveToast.type === 'error'
                  ? 'var(--signal-crit-border)'
                  : waveToast.type === 'info'
                  ? 'var(--cyan-border)'
                  : 'var(--signal-low-border)'
              }`,
              color:
                waveToast.type === 'error'
                  ? 'var(--signal-crit)'
                  : waveToast.type === 'info'
                  ? 'var(--cyan-bright)'
                  : 'var(--signal-low)',
              fontSize: '12px',
              fontFamily: 'var(--font-mono)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              {waveToast.type === 'error' ? (
                <AlertTriangle size={15} />
              ) : waveToast.type === 'info' ? (
                <Loader2 size={15} className="spin" />
              ) : (
                <CheckCircle size={15} />
              )}
              <span>{waveToast.message}</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              {waveToast.type === 'success' && (
                <button
                  className="sec-btn sec-btn-ghost sec-btn-sm"
                  style={{ fontSize: '11px', padding: '3px 8px' }}
                  onClick={() => {
                    setActiveTab('alerts');
                    setWaveToast(null);
                  }}
                >
                  <span>Review in Alert Queue</span>
                  <ArrowRight size={12} />
                </button>
              )}
              <button
                className="sec-btn sec-btn-ghost sec-btn-sm"
                style={{ padding: '2px 6px' }}
                onClick={() => setWaveToast(null)}
              >
                <X size={13} />
              </button>
            </div>
          </div>
        )}

        <main className="page-wrapper">
          {activeTab === 'dashboard' && (
            <Dashboard
              onNavigateAlerts={() => setActiveTab('alerts')}
              onNavigateCases={() => setActiveTab('cases')}
              onSelectAlert={(id) => setSelectedAlertId(id)}
            />
          )}

          {activeTab === 'alerts' && (
            <AlertQueue
              onSelectAlert={(id) => setSelectedAlertId(id)}
              refreshTrigger={refreshTrigger}
            />
          )}

          {activeTab === 'cases' && (
            <CaseManager onSelectAlert={(id) => setSelectedAlertId(id)} />
          )}

          {activeTab === 'topology' && (
            <TopologyPage onSelectAlert={(id) => setSelectedAlertId(id)} />
          )}

          {activeTab === 'geomap' && (
            <GeoMapPage onSelectAlert={(id) => setSelectedAlertId(id)} />
          )}

          {activeTab === 'simulator' && (
            <AttackSimulatorPage
              onSelectAlert={(id) => setSelectedAlertId(id)}
              onAlertGenerated={() => setRefreshTrigger((p) => p + 1)}
            />
          )}

          {activeTab === 'prevention' && <PreventionPage />}

          {activeTab === 'copilot' && <CopilotPage />}

          {activeTab === 'analytics' && <AnalyticsDashboard />}

          {activeTab === 'viva' && <VivaReportPage />}

          {activeTab === 'tests' && <VerificationSuitePage />}

          {activeTab === 'settings' && <SettingsPage />}

          {activeTab === 'login' && (
            <LoginPage onLoginSuccess={handleLoginSuccess} />
          )}
        </main>

        {/* Global Alert Detail Modal */}
        {selectedAlertId && (
          <AlertDetail
            alertId={selectedAlertId}
            onClose={() => setSelectedAlertId(null)}
            onStatusUpdated={handleAlertStatusUpdated}
            onCreateCaseWithAlert={handleCreateCaseWithAlert}
          />
        )}
      </div>
    </div>
  );
}
