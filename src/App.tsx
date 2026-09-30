import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { DashboardOverview } from './pages/DashboardOverview';
import { AlertTriage } from './pages/AlertTriage';
import { IncidentManagement } from './pages/IncidentManagement';
import { EventTelemetry } from './pages/EventTelemetry';
import { DetectionRules } from './pages/DetectionRules';
import { ThreatIntelligence } from './pages/ThreatIntelligence';
import { HostInventory } from './pages/HostInventory';
import { HealthChecker } from './components/HealthChecker';
import { ArchitecturePipeline } from './components/ArchitecturePipeline';
import { fetchHealthStatus } from './services/api';
import { HealthCheckResponse, Alert, Incident } from './types';
import { Shield } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [healthData, setHealthData] = useState<HealthCheckResponse | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [lastChecked, setLastChecked] = useState<string>('');
  const [selectedAlertForTriage, setSelectedAlertForTriage] = useState<Alert | null>(null);
  const [selectedIncidentForTriage, setSelectedIncidentForTriage] = useState<Incident | null>(null);
  const [selectedIndicatorForIntel, setSelectedIndicatorForIntel] = useState<string | null>(null);

  const loadHealth = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const data = await fetchHealthStatus();
      setHealthData(data);
      setLastChecked(new Date().toISOString());
    } catch (err) {
      console.error('Failed to load health status:', err);
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadHealth();
    const interval = setInterval(loadHealth, 30000);
    return () => clearInterval(interval);
  }, [loadHealth]);

  const handleSelectAlert = (alert: Alert) => {
    setSelectedAlertForTriage(alert);
    setActiveTab('alerts');
  };

  const handleSelectIncident = (incident: Incident) => {
    setSelectedIncidentForTriage(incident);
    setActiveTab('incidents');
  };

  const handleNavigateThreatIntel = (indicator: string) => {
    setSelectedIndicatorForIntel(indicator);
    setActiveTab('threat-intel');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-emerald-500/30 selection:text-emerald-300">
      <Header
        onRefresh={loadHealth}
        isRefreshing={isRefreshing}
        overallStatus={healthData?.status || 'healthy'}
        lastChecked={lastChecked}
      />

      <div className="flex-1 flex overflow-hidden">
        <Sidebar activeTab={activeTab} onSelectTab={setActiveTab} />

        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 space-y-6">
          {activeTab === 'dashboard' && (
            <DashboardOverview
              onNavigateTab={setActiveTab}
              onSelectAlert={handleSelectAlert}
              onSelectIncident={handleSelectIncident}
              onNavigateThreatIntel={handleNavigateThreatIntel}
            />
          )}

          {activeTab === 'hosts' && (
            <HostInventory
              onNavigateThreatIntel={handleNavigateThreatIntel}
              onNavigateTab={setActiveTab}
            />
          )}

          {activeTab === 'alerts' && (
            <AlertTriage
              initialSelectedAlert={selectedAlertForTriage}
              onClearSelectedAlert={() => setSelectedAlertForTriage(null)}
              onNavigateTab={setActiveTab}
              onNavigateThreatIntel={handleNavigateThreatIntel}
            />
          )}

          {activeTab === 'incidents' && (
            <IncidentManagement
              initialSelectedIncident={selectedIncidentForTriage}
              onClearSelectedIncident={() => setSelectedIncidentForTriage(null)}
              onNavigateTab={setActiveTab}
            />
          )}

          {activeTab === 'events' && <EventTelemetry />}

          {activeTab === 'threat-intel' && (
            <ThreatIntelligence
              initialIndicator={selectedIndicatorForIntel}
              onSelectAlert={handleSelectAlert}
              onSelectIncident={handleSelectIncident}
            />
          )}

          {activeTab === 'rules' && <DetectionRules />}

          {activeTab === 'pipeline' && (
            <div className="space-y-6">
              <ArchitecturePipeline />
            </div>
          )}

          {activeTab === 'settings' && (
            <div className="space-y-6 font-mono text-xs">
              <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6">
                <h2 className="text-base font-bold text-slate-100 mb-1">
                  SOC Environment & Platform Settings
                </h2>
                <p className="text-slate-400 mb-6">
                  Platform infrastructure, database connection pool, message broker, and background telemetry pipelines.
                </p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="rounded border border-slate-800 bg-slate-950 p-4 space-y-2">
                    <span className="text-emerald-400 font-bold">DATABASE (PostgreSQL 16)</span>
                    <p className="text-slate-400">Host: <span className="text-slate-200">postgres:5432</span></p>
                    <p className="text-slate-400">Database: <span className="text-slate-200">sentinelx_db</span></p>
                    <p className="text-slate-400">Driver: <span className="text-slate-200">asyncpg (SQLAlchemy 2.0 Async)</span></p>
                    <p className="text-slate-400">Migrations: <span className="text-slate-200">004_phase5_threat_intel (Alembic)</span></p>
                  </div>

                  <div className="rounded border border-slate-800 bg-slate-950 p-4 space-y-2">
                    <span className="text-cyan-400 font-bold">REAL-TIME STREAM & BROKER</span>
                    <p className="text-slate-400">Stream Protocol: <span className="text-slate-200">Server-Sent Events (SSE) & WebSocket</span></p>
                    <p className="text-slate-400">Broker: <span className="text-slate-200">Redis 7 pub/sub & Threat Intel Cache</span></p>
                    <p className="text-slate-400">Cache TTL: <span className="text-slate-200">3600s (Configurable)</span></p>
                    <p className="text-slate-400">Client Reconnect: <span className="text-slate-200">Exponential backoff (1s - 16s)</span></p>
                  </div>
                </div>

                <div className="mt-6">
                  <HealthChecker healthData={healthData} onTriggerCheck={loadHealth} isLoading={isRefreshing} />
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
