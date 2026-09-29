import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Flame,
  Activity,
  Layers,
  Crosshair,
  Server,
  Globe,
  Radio,
  ArrowRight,
  TrendingUp,
  Clock,
  Play,
} from 'lucide-react';
import { DashboardStats, Alert, Incident, SecurityEvent } from '../types';
import { fetchDashboardStats, ingestEvent } from '../services/api';
import { RealtimeIndicator } from '../components/RealtimeIndicator';
import { SeverityBadge } from '../components/SeverityBadge';
import { RiskScoreMeter } from '../components/RiskScoreMeter';
import { useRealtime } from '../services/realtime';

interface DashboardOverviewProps {
  onNavigateTab: (tabId: string) => void;
  onSelectAlert?: (alert: Alert) => void;
  onSelectIncident?: (incident: Incident) => void;
  onNavigateThreatIntel?: (indicator: string) => void;
}

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  onNavigateTab,
  onSelectAlert,
  onSelectIncident,
  onNavigateThreatIntel,
}) => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [simulating, setSimulating] = useState(false);
  const [simulationLog, setSimulationLog] = useState<string | null>(null);

  const loadStats = useCallback(async () => {
    try {
      const data = await fetchDashboardStats();
      setStats(data);
    } catch (err) {
      console.error('Failed to load dashboard metrics:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  // Listen to real-time events via SSE
  const { status: realtimeStatus, reconnect } = useRealtime(
    useCallback((data: any) => {
      // Whenever a new alert, incident, or update arrives, re-fetch stats
      if (['new_alert', 'alert_updated', 'new_incident', 'incident_updated', 'new_event'].includes(data.type)) {
        loadStats();
      }
    }, [loadStats])
  );

  useEffect(() => {
    loadStats();
    const interval = setInterval(loadStats, 20000);
    return () => clearInterval(interval);
  }, [loadStats]);

  const handleSimulateAttack = async (type: 'port_scan' | 'ssh_brute' | 'sqli' | 'syn_flood') => {
    setSimulating(true);
    setSimulationLog(null);
    try {
      let payload: any = {};
      if (type === 'port_scan') {
        payload = {
          event_type: 'port_scan',
          source: 'network',
          source_ip: '192.0.2.144',
          destination_ip: '10.0.0.15',
          destination_port: 80,
          protocol: 'TCP',
          severity: 'HIGH',
          message: 'Safe synthetic port scan probing destination web services',
          mitre_technique: 'T1046',
        };
      } else if (type === 'ssh_brute') {
        payload = {
          event_type: 'authentication_failure',
          source: 'linux-agent',
          source_ip: '198.51.100.89',
          destination_ip: '10.0.0.20',
          destination_port: 22,
          protocol: 'TCP',
          severity: 'HIGH',
          username: 'root',
          hostname: 'PROD-AUTH-01',
          message: 'Repeated failed password for root via sshd from external address',
          mitre_technique: 'T1110.001',
        };
      } else if (type === 'sqli') {
        payload = {
          event_type: 'http_request',
          source: 'web-waf',
          source_ip: '203.0.113.88',
          destination_ip: '10.0.0.30',
          destination_port: 443,
          protocol: 'HTTP',
          severity: 'HIGH',
          hostname: 'PROD-WEB-API',
          message: "POST /api/v1/auth - payload: admin' OR '1'='1' --",
          mitre_technique: 'T1190',
        };
      } else if (type === 'syn_flood') {
        payload = {
          event_type: 'syn_flood_burst',
          source: 'network-switch',
          source_ip: '192.0.2.200',
          destination_ip: '10.0.0.1',
          destination_port: 80,
          protocol: 'TCP',
          severity: 'CRITICAL',
          message: 'SYN flood burst anomaly exceeding 50,000 packets/sec rate limit',
          mitre_technique: 'T1498',
        };
      }

      const res = await ingestEvent(payload);
      setSimulationLog(
        `Generated ${res.generated_alerts.length} detection alert(s) for event ${res.event_ids[0]}. Pushed to real-time stream.`
      );
      loadStats();
    } catch (err: any) {
      setSimulationLog(`Simulation failed: ${err.message}`);
    } finally {
      setSimulating(false);
    }
  };

  const overview = stats?.executive_overview;
  const sevCounts = stats?.severity_counts;
  const riskDist = stats?.risk_distribution;

  return (
    <div className="space-y-6">
      {/* Top Banner: Executive Posture & Real-time Indicator */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div
            className={`flex h-12 w-12 items-center justify-center rounded-lg border font-mono font-bold ${
              overview?.defense_status === 'CRITICAL ALERT'
                ? 'bg-rose-950/80 border-rose-800 text-rose-400'
                : overview?.defense_status === 'ELEVATED'
                ? 'bg-amber-950/80 border-amber-800 text-amber-400'
                : 'bg-emerald-950/80 border-emerald-800 text-emerald-400'
            }`}
          >
            {overview?.defense_status === 'CRITICAL ALERT' ? (
              <Flame className="h-6 w-6 animate-pulse" />
            ) : overview?.defense_status === 'ELEVATED' ? (
              <AlertTriangle className="h-6 w-6" />
            ) : (
              <ShieldCheck className="h-6 w-6" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono uppercase tracking-wider text-slate-400">SOC DEFENSE POSTURE:</span>
              <span
                className={`font-mono font-bold text-sm px-2 py-0.5 rounded border ${
                  overview?.defense_status === 'CRITICAL ALERT'
                    ? 'text-rose-400 border-rose-800 bg-rose-950/40'
                    : overview?.defense_status === 'ELEVATED'
                    ? 'text-amber-400 border-amber-800 bg-amber-950/40'
                    : 'text-emerald-400 border-emerald-800 bg-emerald-950/40'
                }`}
              >
                {overview?.defense_status || 'DEFENDING'}
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Continuous threat detection • {overview?.tactics_covered || 0}/{overview?.total_rules || 8} MITRE ATT&CK Tactics Covered
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <RealtimeIndicator status={realtimeStatus} onReconnect={reconnect} />
        </div>
      </div>

      {/* Executive Security Overview: Key KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-1">
            <span>ACTIVE ALERTS</span>
            <AlertTriangle className="h-4 w-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100">{overview?.active_alerts ?? 0}</div>
          <div className="text-[11px] text-slate-500 font-mono mt-1">Total: {overview?.total_alerts ?? 0}</div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-1">
            <span>OPEN INCIDENTS</span>
            <Flame className="h-4 w-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100">{overview?.open_incidents ?? 0}</div>
          <div className="text-[11px] text-slate-500 font-mono mt-1">Multi-event correlated</div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-1">
            <span>CRITICAL SEVERITY</span>
            <ShieldAlert className="h-4 w-4 text-rose-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-400">{overview?.critical_alerts ?? 0}</div>
          <div className="text-[11px] text-rose-500/80 font-mono mt-1">Immediate action req.</div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-1">
            <span>AVG RISK SCORE</span>
            <Crosshair className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-cyan-400">
            {overview?.average_risk_score ?? 0}
            <span className="text-xs text-slate-500 font-normal">/100</span>
          </div>
          <div className="text-[11px] text-slate-500 font-mono mt-1">Explainable metric</div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-1">
            <span>EVENTS INGESTED</span>
            <Activity className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">{overview?.total_events ?? 0}</div>
          <div className="text-[11px] text-slate-500 font-mono mt-1">PostgreSQL indexed</div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs font-mono mb-1">
            <span>DETECTION RULES</span>
            <Layers className="h-4 w-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100">{overview?.total_rules ?? 8}</div>
          <div className="text-[11px] text-slate-500 font-mono mt-1">Active analyzers</div>
        </div>
      </div>

      {/* Synthetic Attack Testing Panel */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-4 font-mono text-xs">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-2">
          <div className="flex items-center gap-2 text-slate-200">
            <Play className="h-4 w-4 text-emerald-400" />
            <span className="font-bold">LIVE TELEMETRY & ATTACK SIMULATOR (SAFE RFC 5737 TEST TRAFFIC)</span>
          </div>
          <span className="text-[11px] text-slate-500">Injects test events into the pipeline & broadcasts via SSE</span>
        </div>
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <button
            onClick={() => handleSimulateAttack('port_scan')}
            disabled={simulating}
            className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition cursor-pointer disabled:opacity-50"
          >
            Simulate Port Scan (T1046)
          </button>
          <button
            onClick={() => handleSimulateAttack('ssh_brute')}
            disabled={simulating}
            className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition cursor-pointer disabled:opacity-50"
          >
            Simulate SSH Brute Force (T1110.001)
          </button>
          <button
            onClick={() => handleSimulateAttack('sqli')}
            disabled={simulating}
            className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition cursor-pointer disabled:opacity-50"
          >
            Simulate Web SQLi Attack (T1190)
          </button>
          <button
            onClick={() => handleSimulateAttack('syn_flood')}
            disabled={simulating}
            className="px-3 py-1.5 rounded bg-rose-950/60 hover:bg-rose-900/60 text-rose-300 border border-rose-800/80 transition cursor-pointer disabled:opacity-50"
          >
            Simulate SYN Flood (T1498)
          </button>
        </div>
        {simulationLog && (
          <div className="mt-2 text-emerald-400 bg-emerald-950/30 border border-emerald-900/50 p-2 rounded text-[11px]">
            {simulationLog}
          </div>
        )}
      </div>

      {/* Row 2: Severity Distribution + Risk Distribution + Event Timeline */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Counts */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
              Alerts by Severity
            </h3>
            <span className="text-xs font-mono text-slate-500">Breakdown</span>
          </div>

          <div className="space-y-3 font-mono text-xs">
            <div>
              <div className="flex justify-between text-slate-400 mb-1">
                <span className="flex items-center gap-1.5 text-rose-400 font-semibold">
                  <span className="h-2 w-2 rounded-full bg-rose-500" /> CRITICAL
                </span>
                <span>{sevCounts?.CRITICAL ?? 0}</span>
              </div>
              <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-rose-500"
                  style={{
                    width: `${Math.min(100, ((sevCounts?.CRITICAL ?? 0) / (overview?.total_alerts || 1)) * 100)}%`,
                  }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-slate-400 mb-1">
                <span className="flex items-center gap-1.5 text-orange-400 font-semibold">
                  <span className="h-2 w-2 rounded-full bg-orange-500" /> HIGH
                </span>
                <span>{sevCounts?.HIGH ?? 0}</span>
              </div>
              <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-orange-500"
                  style={{
                    width: `${Math.min(100, ((sevCounts?.HIGH ?? 0) / (overview?.total_alerts || 1)) * 100)}%`,
                  }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-slate-400 mb-1">
                <span className="flex items-center gap-1.5 text-amber-400 font-semibold">
                  <span className="h-2 w-2 rounded-full bg-amber-500" /> MEDIUM
                </span>
                <span>{sevCounts?.MEDIUM ?? 0}</span>
              </div>
              <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-amber-500"
                  style={{
                    width: `${Math.min(100, ((sevCounts?.MEDIUM ?? 0) / (overview?.total_alerts || 1)) * 100)}%`,
                  }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-slate-400 mb-1">
                <span className="flex items-center gap-1.5 text-blue-400 font-semibold">
                  <span className="h-2 w-2 rounded-full bg-blue-500" /> LOW
                </span>
                <span>{sevCounts?.LOW ?? 0}</span>
              </div>
              <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-blue-500"
                  style={{
                    width: `${Math.min(100, ((sevCounts?.LOW ?? 0) / (overview?.total_alerts || 1)) * 100)}%`,
                  }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-slate-400 mb-1">
                <span className="flex items-center gap-1.5 text-slate-400 font-semibold">
                  <span className="h-2 w-2 rounded-full bg-slate-500" /> INFORMATIONAL
                </span>
                <span>{sevCounts?.INFORMATIONAL ?? 0}</span>
              </div>
              <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-slate-500"
                  style={{
                    width: `${Math.min(100, ((sevCounts?.INFORMATIONAL ?? 0) / (overview?.total_alerts || 1)) * 100)}%`,
                  }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Risk Score Distribution */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
              Risk Score Distribution
            </h3>
            <span className="text-xs font-mono text-slate-500">0 - 100 Scale</span>
          </div>

          <div className="grid grid-cols-2 gap-3 font-mono text-xs">
            <div className="rounded border border-slate-800 bg-slate-950 p-3">
              <span className="text-[10px] text-slate-400 uppercase">Low (0-24)</span>
              <div className="text-xl font-bold text-emerald-400 mt-1">{riskDist?.['0-24 (Low)'] ?? 0}</div>
            </div>
            <div className="rounded border border-slate-800 bg-slate-950 p-3">
              <span className="text-[10px] text-slate-400 uppercase">Guarded (25-49)</span>
              <div className="text-xl font-bold text-blue-400 mt-1">{riskDist?.['25-49 (Guarded)'] ?? 0}</div>
            </div>
            <div className="rounded border border-slate-800 bg-slate-950 p-3">
              <span className="text-[10px] text-slate-400 uppercase">Elevated (50-74)</span>
              <div className="text-xl font-bold text-amber-400 mt-1">{riskDist?.['50-74 (Elevated)'] ?? 0}</div>
            </div>
            <div className="rounded border border-slate-800 bg-slate-950 p-3">
              <span className="text-[10px] text-slate-400 uppercase">Severe (75-100)</span>
              <div className="text-xl font-bold text-rose-400 mt-1">{riskDist?.['75-100 (Severe)'] ?? 0}</div>
            </div>
          </div>
        </div>

        {/* Event Volume Timeline */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
              Event Volume Timeline
            </h3>
            <span className="text-xs font-mono text-slate-500">Hourly Rate</span>
          </div>

          <div className="h-36 flex items-end gap-3 pt-4 px-1">
            {stats?.event_timeline?.map((item, idx) => (
              <div key={idx} className="flex-1 flex flex-col items-center gap-1.5 h-full justify-end">
                <div className="w-full flex items-end justify-center gap-1 h-24">
                  {/* Event bar */}
                  <div
                    className="w-1/2 bg-emerald-500/80 rounded-t hover:bg-emerald-400 transition"
                    style={{ height: `${Math.min(100, Math.max(10, item.events * 10))}%` }}
                    title={`Events: ${item.events}`}
                  />
                  {/* Alert bar */}
                  <div
                    className="w-1/2 bg-rose-500/80 rounded-t hover:bg-rose-400 transition"
                    style={{ height: `${Math.min(100, Math.max(6, item.alerts * 20))}%` }}
                    title={`Alerts: ${item.alerts}`}
                  />
                </div>
                <span className="text-[10px] font-mono text-slate-400">{item.time}</span>
              </div>
            ))}
          </div>
          <div className="flex items-center justify-center gap-4 text-[10px] font-mono text-slate-400 mt-2">
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded bg-emerald-500" /> Ingested Events
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded bg-rose-500" /> Triggered Alerts
            </span>
          </div>
        </div>
      </div>

      {/* Row 3: Active Alerts & Open Incidents quick tables */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Active Alerts */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                Recent Security Alerts
              </h3>
            </div>
            <button
              onClick={() => onNavigateTab('alerts')}
              className="inline-flex items-center gap-1 text-xs font-mono text-emerald-400 hover:underline cursor-pointer"
            >
              <span>View All Alerts</span>
              <ArrowRight className="h-3 w-3" />
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-500 text-[11px]">
                  <th className="pb-2 font-normal">SEV</th>
                  <th className="pb-2 font-normal">TITLE</th>
                  <th className="pb-2 font-normal">RISK</th>
                  <th className="pb-2 font-normal">STATUS</th>
                  <th className="pb-2 font-normal">MITRE</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {stats?.recent_alerts?.slice(0, 5).map((alert) => (
                  <tr
                    key={alert.id}
                    onClick={() => {
                      if (onSelectAlert) onSelectAlert(alert);
                      onNavigateTab('alerts');
                    }}
                    className="hover:bg-slate-800/50 cursor-pointer transition"
                  >
                    <td className="py-2.5 pr-2">
                      <SeverityBadge severity={alert.severity} size="sm" />
                    </td>
                    <td className="py-2.5 pr-2 font-medium text-slate-200 max-w-[200px] truncate" title={alert.title}>
                      {alert.title}
                    </td>
                    <td className="py-2.5 pr-2">
                      <RiskScoreMeter score={alert.risk_score} />
                    </td>
                    <td className="py-2.5 pr-2 text-slate-300">{alert.status}</td>
                    <td className="py-2.5 text-cyan-400">{alert.mitre_technique || 'N/A'}</td>
                  </tr>
                ))}
                {(!stats?.recent_alerts || stats.recent_alerts.length === 0) && (
                  <tr>
                    <td colSpan={5} className="py-6 text-center text-slate-500">
                      No active security alerts recorded.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Open Incidents */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Flame className="h-4 w-4 text-rose-400" />
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                Correlated Incidents
              </h3>
            </div>
            <button
              onClick={() => onNavigateTab('incidents')}
              className="inline-flex items-center gap-1 text-xs font-mono text-emerald-400 hover:underline cursor-pointer"
            >
              <span>View Incidents</span>
              <ArrowRight className="h-3 w-3" />
            </button>
          </div>

          <div className="space-y-3">
            {stats?.recent_incidents?.map((inc) => (
              <div
                key={inc.id}
                onClick={() => {
                  if (onSelectIncident) onSelectIncident(inc);
                  onNavigateTab('incidents');
                }}
                className="rounded-lg border border-slate-800 bg-slate-950 p-3 hover:border-slate-700 transition cursor-pointer"
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-mono text-xs font-bold text-slate-200">{inc.title}</span>
                  <SeverityBadge severity={inc.severity} size="sm" />
                </div>
                <p className="text-xs text-slate-400 line-clamp-2 mb-2 font-mono">{inc.description}</p>
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-500">
                  <span className="text-amber-400 font-semibold">STATUS: {inc.status}</span>
                  <RiskScoreMeter score={inc.risk_score} />
                </div>
              </div>
            ))}
            {(!stats?.recent_incidents || stats.recent_incidents.length === 0) && (
              <div className="py-8 text-center text-xs font-mono text-slate-500">
                No active correlated incidents. Detection correlation engine monitoring streams.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Row 4: Top Sources & Assets + MITRE ATT&CK Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Top Source IPs */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Globe className="h-4 w-4 text-cyan-400" />
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                Top Source IPs
              </h3>
            </div>
            <span className="text-xs font-mono text-slate-500">Telemetry Origin</span>
          </div>

          <div className="space-y-2 font-mono text-xs">
            {stats?.top_source_ips?.map((s, idx) => (
              <div
                key={idx}
                onClick={() => {
                  if (onNavigateThreatIntel) onNavigateThreatIntel(s.ip);
                  else onNavigateTab('threat-intel');
                }}
                className="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800 hover:border-cyan-500/50 cursor-pointer transition group"
                title="Click to view Threat Intelligence"
              >
                <span className="text-slate-300 group-hover:text-cyan-400 font-semibold">{s.ip}</span>
                <span className="px-2 py-0.5 rounded bg-slate-900 text-cyan-400 border border-slate-800 font-semibold group-hover:bg-cyan-950">
                  {s.event_count} events
                </span>
              </div>
            ))}
            {(!stats?.top_source_ips || stats.top_source_ips.length === 0) && (
              <div className="py-4 text-center text-slate-500">No external source IPs recorded.</div>
            )}
          </div>
        </div>

        {/* Top Affected Assets */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4 text-indigo-400" />
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                Top Affected Assets
              </h3>
            </div>
            <span className="text-xs font-mono text-slate-500">Target Destinations</span>
          </div>

          <div className="space-y-2 font-mono text-xs">
            {stats?.top_affected_assets?.map((a, idx) => (
              <div key={idx} className="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800">
                <span className="text-slate-300">{a.asset}</span>
                <span className="px-2 py-0.5 rounded bg-slate-900 text-indigo-400 border border-slate-800 font-semibold">
                  {a.event_count} hits
                </span>
              </div>
            ))}
            {(!stats?.top_affected_assets || stats.top_affected_assets.length === 0) && (
              <div className="py-4 text-center text-slate-500">No destination telemetry targets recorded.</div>
            )}
          </div>
        </div>

        {/* MITRE ATT&CK Matrix Coverage */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Crosshair className="h-4 w-4 text-emerald-400" />
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-300">
                MITRE ATT&CK Matrix
              </h3>
            </div>
            <span className="text-xs font-mono text-slate-500">Active Coverage</span>
          </div>

          <div className="grid grid-cols-2 gap-2 font-mono text-xs">
            {stats?.mitre_coverage?.map((m) => (
              <div
                key={m.id}
                className={`p-2 rounded border transition ${
                  m.is_active
                    ? 'border-emerald-800/80 bg-emerald-950/40 text-emerald-300'
                    : 'border-slate-800/80 bg-slate-950/60 text-slate-500'
                }`}
              >
                <div className="flex items-center justify-between text-[11px] font-bold">
                  <span>{m.id}</span>
                  {m.is_active && (
                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  )}
                </div>
                <div className="text-[11px] truncate mt-0.5 text-slate-300" title={m.technique}>
                  {m.technique}
                </div>
                <div className="text-[9px] uppercase tracking-wider text-slate-500 mt-1">
                  {m.tactic}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
