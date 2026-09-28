import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { DashboardOverview } from './pages/DashboardOverview';
import { fetchHealthStatus } from './services/api';
import { HealthCheckResponse } from './types';
import { Shield, AlertTriangle } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [healthData, setHealthData] = useState<HealthCheckResponse | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [lastChecked, setLastChecked] = useState<string>('');

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
    // Periodic polling every 30 seconds
    const interval = setInterval(loadHealth, 30000);
    return () => clearInterval(interval);
  }, [loadHealth]);

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
              healthData={healthData}
              onRefreshHealth={loadHealth}
              isLoading={isRefreshing}
            />
          )}

          {activeTab === 'pipeline' && (
            <div className="space-y-6">
              <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6">
                <h2 className="text-lg font-bold text-slate-100 mb-2 font-mono">
                  Full End-to-End Pipeline Specification
                </h2>
                <p className="text-xs text-slate-400 mb-6 max-w-2xl">
                  SentinelX processes raw telemetry through 10 deterministic stages to eliminate alert fatigue
                  and produce high-confidence actionable incidents.
                </p>
                <DashboardOverview
                  healthData={healthData}
                  onRefreshHealth={loadHealth}
                  isLoading={isRefreshing}
                />
              </div>
            </div>
          )}

          {activeTab === 'settings' && (
            <div className="space-y-6">
              <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6">
                <h2 className="text-lg font-bold text-slate-100 mb-1 font-mono">
                  Environment & Platform Settings
                </h2>
                <p className="text-xs text-slate-400 mb-6">
                  Phase 1 configuration attributes loaded from environment and Pydantic settings.
                </p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                  <div className="rounded border border-slate-800 bg-slate-950 p-4 space-y-2">
                    <span className="text-emerald-400 font-bold">DATABASE (PostgreSQL)</span>
                    <p className="text-slate-400">Host: <span className="text-slate-200">postgres:5432</span></p>
                    <p className="text-slate-400">Driver: <span className="text-slate-200">asyncpg (SQLAlchemy 2.0 Async)</span></p>
                    <p className="text-slate-400">Pool Size: <span className="text-slate-200">10 connections (max 20 overflow)</span></p>
                  </div>

                  <div className="rounded border border-slate-800 bg-slate-950 p-4 space-y-2">
                    <span className="text-cyan-400 font-bold">MESSAGE BROKER (Redis)</span>
                    <p className="text-slate-400">Host: <span className="text-slate-200">redis:6379</span></p>
                    <p className="text-slate-400">Driver: <span className="text-slate-200">redis.asyncio</span></p>
                    <p className="text-slate-400">Database Index: <span className="text-slate-200">0</span></p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab !== 'dashboard' && activeTab !== 'pipeline' && activeTab !== 'settings' && (
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-12 text-center space-y-3">
              <div className="inline-flex p-3 rounded-full bg-slate-800 text-slate-400 mb-2">
                <Shield className="h-6 w-6" />
              </div>
              <h3 className="text-base font-bold text-slate-200 font-mono">
                Subsystem Scheduled for Subsequent Phase
              </h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                This capability will be activated in accordance with the Phase Roadmap (Phase 2: Auth & Models, Phase 3: Ingestion, Phase 4: Rules, Phase 5: Incidents).
              </p>
              <button
                onClick={() => setActiveTab('dashboard')}
                className="mt-4 rounded bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 px-4 py-2 text-xs font-mono font-medium transition cursor-pointer"
              >
                Return to SOC Dashboard
              </button>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
