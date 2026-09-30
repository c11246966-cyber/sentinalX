import React, { useState, useEffect, useCallback } from 'react';
import {
  BellRing,
  Search,
  Filter,
  ArrowUpDown,
  ExternalLink,
  ShieldAlert,
  Clock,
  CheckCircle2,
  XCircle,
  FileEdit,
  Save,
  Flame,
  Globe,
  Radio,
  X,
  RefreshCw,
  Globe2,
} from 'lucide-react';
import { Alert, AlertStatus, AlertSeverity } from '../types';
import { fetchAlerts, fetchAlertById, updateAlert, createIncident } from '../services/api';
import { SeverityBadge } from '../components/SeverityBadge';
import { RiskScoreMeter } from '../components/RiskScoreMeter';
import { useRealtime } from '../services/realtime';

interface AlertTriageProps {
  initialSelectedAlert?: Alert | null;
  onClearSelectedAlert?: () => void;
  onNavigateTab?: (tab: string) => void;
  onNavigateThreatIntel?: (indicator: string) => void;
}

export const AlertTriage: React.FC<AlertTriageProps> = ({
  initialSelectedAlert,
  onClearSelectedAlert,
  onNavigateTab,
  onNavigateThreatIntel,
}) => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(initialSelectedAlert || null);
  const [analystNotes, setAnalystNotes] = useState('');
  const [savingNotes, setSavingNotes] = useState(false);
  const [escalating, setEscalating] = useState(false);
  const [notification, setNotification] = useState<string | null>(null);

  // Filters
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [mitreFilter, setMitreFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');

  const loadAlerts = useCallback(async () => {
    try {
      const data = await fetchAlerts({
        status: statusFilter,
        severity: severityFilter,
        source_ip: sourceFilter || undefined,
        mitre_technique: mitreFilter || undefined,
      });
      setAlerts(data);
    } catch (err) {
      console.error('Failed to load alerts:', err);
    } finally {
      setLoading(false);
    }
  }, [statusFilter, severityFilter, sourceFilter, mitreFilter]);

  // Real-time updates via WebSocket
  useRealtime(
    useCallback((data: any) => {
      if (['alert.created', 'alert.updated', 'new_alert', 'alert_updated'].includes(data.type)) {
        loadAlerts();
        const alertObj = data.alert || data.data;
        if (selectedAlert && alertObj && alertObj.id === selectedAlert.id) {
          setSelectedAlert((prev) => (prev ? { ...prev, ...alertObj } : null));
        }
      }
    }, [loadAlerts, selectedAlert])
  );

  useEffect(() => {
    loadAlerts();
  }, [loadAlerts]);

  useEffect(() => {
    if (initialSelectedAlert) {
      handleSelectAlert(initialSelectedAlert);
    }
  }, [initialSelectedAlert]);

  const handleSelectAlert = async (alert: Alert) => {
    try {
      const detail = await fetchAlertById(alert.id);
      setSelectedAlert(detail);
      setAnalystNotes(detail.analyst_notes || '');
    } catch {
      setSelectedAlert(alert);
      setAnalystNotes(alert.analyst_notes || '');
    }
  };

  const handleStatusChange = async (newStatus: AlertStatus) => {
    if (!selectedAlert) return;
    try {
      const updated = await updateAlert(selectedAlert.id, { status: newStatus });
      setSelectedAlert(updated);
      setAlerts((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
      setNotification(`Alert #${selectedAlert.id} status transitioned to ${newStatus}`);
      setTimeout(() => setNotification(null), 4000);
    } catch (err: any) {
      setNotification(`Failed to update status: ${err.message}`);
    }
  };

  const handleSaveNotes = async () => {
    if (!selectedAlert) return;
    setSavingNotes(true);
    try {
      const updated = await updateAlert(selectedAlert.id, { analyst_notes: analystNotes });
      setSelectedAlert(updated);
      setAlerts((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
      setNotification('Analyst notes committed to audit trail.');
      setTimeout(() => setNotification(null), 3000);
    } catch (err: any) {
      setNotification(`Error saving notes: ${err.message}`);
    } finally {
      setSavingNotes(false);
    }
  };

  const handleEscalateToIncident = async () => {
    if (!selectedAlert) return;
    setEscalating(true);
    try {
      const incident = await createIncident({
        title: `Incident: ${selectedAlert.title}`,
        description: `Correlated escalation from Alert #${selectedAlert.id}: ${selectedAlert.description}`,
        severity: selectedAlert.severity,
        risk_score: selectedAlert.risk_score,
        alert_ids: [selectedAlert.id],
        analyst_notes: `Escalated directly from alert triage drawer. Initial notes: ${analystNotes || 'None'}`,
      });
      setNotification(`Escalated to Incident #${incident.id}!`);
      setTimeout(() => {
        setNotification(null);
        if (onNavigateTab) onNavigateTab('incidents');
      }, 1500);
    } catch (err: any) {
      setNotification(`Escalation failed: ${err.message}`);
    } finally {
      setEscalating(false);
    }
  };

  const filteredAlerts = alerts.filter((a) => {
    if (search) {
      const q = search.toLowerCase();
      const match =
        a.title.toLowerCase().includes(q) ||
        a.description.toLowerCase().includes(q) ||
        (a.source_ip && a.source_ip.includes(q)) ||
        (a.mitre_technique && a.mitre_technique.toLowerCase().includes(q));
      if (!match) return false;
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <BellRing className="h-5 w-5 text-amber-400" />
            <h2 className="text-lg font-bold font-mono text-slate-100 uppercase tracking-wide">
              Alert Triage & Investigation
            </h2>
            <span className="rounded bg-slate-800 px-2 py-0.5 text-xs font-mono text-slate-300">
              {filteredAlerts.length} Active Records
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Real-time rule-based detection stream with MITRE ATT&CK mapping & analyst response lifecycle
          </p>
        </div>

        <button
          onClick={loadAlerts}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-mono text-xs cursor-pointer"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {notification && (
        <div className="rounded border border-emerald-800 bg-emerald-950/80 p-3 text-xs font-mono text-emerald-300 flex items-center justify-between">
          <span>{notification}</span>
          <button onClick={() => setNotification(null)} className="cursor-pointer">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Filter Toolbar */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 font-mono text-xs space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search title, IP, technique..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500/50"
            />
          </div>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-emerald-500/50"
          >
            <option value="ALL">Status: All Statuses</option>
            <option value="NEW">NEW</option>
            <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="RESOLVED">RESOLVED</option>
            <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
          </select>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-emerald-500/50"
          >
            <option value="ALL">Severity: All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
            <option value="INFORMATIONAL">INFORMATIONAL</option>
          </select>

          {/* MITRE Filter */}
          <input
            type="text"
            placeholder="MITRE ID (e.g. T1046)"
            value={mitreFilter}
            onChange={(e) => setMitreFilter(e.target.value)}
            className="px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500/50"
          />

          {/* Source IP Filter */}
          <input
            type="text"
            placeholder="Source IP..."
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            className="px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500/50"
          />
        </div>
      </div>

      {/* Main Grid: Alert List + Detail Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Table of Alerts (Takes 7 cols or full width) */}
        <div className={`space-y-4 ${selectedAlert ? 'lg:col-span-7' : 'lg:col-span-12'}`}>
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-950 border-b border-slate-800 text-slate-400 text-[11px]">
                  <tr>
                    <th className="py-3 px-4">SEVERITY</th>
                    <th className="py-3 px-4">ALERT TITLE</th>
                    <th className="py-3 px-4">RISK</th>
                    <th className="py-3 px-4">SOURCE → DEST</th>
                    <th className="py-3 px-4">TECHNIQUE</th>
                    <th className="py-3 px-4">STATUS</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredAlerts.map((alert) => {
                    const isSelected = selectedAlert?.id === alert.id;
                    return (
                      <tr
                        key={alert.id}
                        onClick={() => handleSelectAlert(alert)}
                        className={`hover:bg-slate-800/50 cursor-pointer transition ${
                          isSelected ? 'bg-emerald-950/20 border-l-2 border-emerald-500' : ''
                        }`}
                      >
                        <td className="py-3 px-4">
                          <SeverityBadge severity={alert.severity} size="sm" />
                        </td>
                        <td className="py-3 px-4 font-semibold text-slate-200 max-w-[220px] truncate">
                          {alert.title}
                        </td>
                        <td className="py-3 px-4">
                          <RiskScoreMeter score={alert.risk_score} />
                        </td>
                        <td className="py-3 px-4 text-slate-400">
                          {alert.source_ip || 'Internal'} → {alert.destination_ip || 'Host'}
                        </td>
                        <td className="py-3 px-4 text-cyan-400 font-bold">
                          {alert.mitre_technique || '—'}
                        </td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${
                              alert.status === 'NEW'
                                ? 'bg-amber-950/60 text-amber-300 border-amber-800'
                                : alert.status === 'INVESTIGATING'
                                ? 'bg-blue-950/60 text-blue-300 border-blue-800'
                                : alert.status === 'RESOLVED'
                                ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800'
                                : alert.status === 'FALSE_POSITIVE'
                                ? 'bg-slate-900 text-slate-400 border-slate-700'
                                : 'bg-slate-800 text-slate-300 border-slate-700'
                            }`}
                          >
                            {alert.status}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                  {filteredAlerts.length === 0 && (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-500 font-mono">
                        No alerts match the active filter criteria.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Selected Alert Detail Drawer (5 cols) */}
        {selectedAlert && (
          <div className="lg:col-span-5 space-y-4">
            <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 space-y-5 font-mono text-xs">
              {/* Header */}
              <div className="flex items-start justify-between gap-2 border-b border-slate-800 pb-3">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-slate-400 font-bold">ALERT #{selectedAlert.id}</span>
                    <SeverityBadge severity={selectedAlert.severity} size="sm" />
                  </div>
                  <h3 className="text-sm font-bold text-slate-100">{selectedAlert.title}</h3>
                </div>
                <button
                  onClick={() => setSelectedAlert(null)}
                  className="text-slate-400 hover:text-slate-200 cursor-pointer p-1"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              {/* Status Triage Controls */}
              <div>
                <span className="text-[11px] text-slate-500 uppercase font-bold block mb-2">
                  SOC Triage Lifecycle Transition:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {(['NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'] as AlertStatus[]).map(
                    (st) => (
                      <button
                        key={st}
                        onClick={() => handleStatusChange(st)}
                        className={`px-2.5 py-1 rounded text-[11px] font-bold border transition cursor-pointer ${
                          selectedAlert.status === st
                            ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500'
                            : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-700'
                        }`}
                      >
                        {st}
                      </button>
                    )
                  )}
                </div>
              </div>

              {/* Threat & Evidence Details */}
              <div className="grid grid-cols-2 gap-3 bg-slate-950 p-3 rounded border border-slate-800">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase">Risk Score</span>
                  <div className="mt-1">
                    <RiskScoreMeter score={selectedAlert.risk_score} showBar={true} />
                  </div>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 uppercase">Detection Rule</span>
                  <div className="text-slate-200 mt-1 font-semibold">{selectedAlert.mitre_tactic || 'Rule Trigger'}</div>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 uppercase">Source IP</span>
                  <div className="text-slate-200 mt-1">{selectedAlert.source_ip || 'None'}</div>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 uppercase">Destination IP</span>
                  <div className="text-slate-200 mt-1">{selectedAlert.destination_ip || 'Local Network'}</div>
                </div>
              </div>

              {/* Description */}
              <div>
                <span className="text-[11px] text-slate-500 uppercase font-bold block mb-1">
                  Alert Description & Context:
                </span>
                <p className="p-3 rounded bg-slate-950 border border-slate-800 text-slate-300 text-xs leading-relaxed">
                  {selectedAlert.description}
                </p>
              </div>

              {/* MITRE ATT&CK Mapping */}
              {selectedAlert.mitre_technique && (
                <div className="rounded border border-cyan-900/60 bg-cyan-950/20 p-3 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-cyan-400 font-bold">
                      MITRE ATT&CK: {selectedAlert.mitre_technique}
                    </span>
                    <a
                      href={`https://attack.mitre.org/techniques/${selectedAlert.mitre_technique.replace('.', '/')}/`}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 text-[11px] text-cyan-400 hover:underline"
                    >
                      <span>Framework Reference</span>
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Tactic: <span className="text-slate-200 font-semibold">{selectedAlert.mitre_tactic || 'Reconnaissance'}</span>
                  </p>
                </div>
              )}

              {/* Phase 5 Threat Intelligence Enrichment & Risk Adjustment */}
              {(selectedAlert.threat_intel_context || selectedAlert.risk_adjustment_reason || selectedAlert.source_ip) && (
                <div className="rounded-lg border border-purple-900/60 bg-purple-950/20 p-3 space-y-2.5 font-mono">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 text-purple-300 font-bold text-xs">
                      <Globe2 className="h-3.5 w-3.5 text-purple-400" />
                      <span>THREAT INTELLIGENCE & IOC CONTEXT</span>
                    </div>
                    {selectedAlert.source_ip && onNavigateThreatIntel && (
                      <button
                        onClick={() => onNavigateThreatIntel(selectedAlert.source_ip!)}
                        className="inline-flex items-center gap-1 text-[10px] text-purple-400 hover:text-purple-200 transition"
                      >
                        <span>Deep Lookup</span>
                        <ExternalLink className="h-3 w-3" />
                      </button>
                    )}
                  </div>

                  {selectedAlert.threat_intel_context ? (
                    <div className="space-y-2 text-xs">
                      <div className="flex items-center justify-between bg-slate-950 p-2 rounded border border-purple-900/40">
                        <span className="text-slate-400">Reputation:</span>
                        <span className={`font-bold uppercase ${
                          selectedAlert.threat_intel_context.reputation === 'malicious'
                            ? 'text-rose-400'
                            : selectedAlert.threat_intel_context.reputation === 'suspicious'
                            ? 'text-amber-400'
                            : selectedAlert.threat_intel_context.reputation === 'clean'
                            ? 'text-emerald-400'
                            : 'text-slate-400'
                        }`}>
                          {selectedAlert.threat_intel_context.reputation}
                        </span>
                      </div>
                      <div className="flex items-center justify-between bg-slate-950 p-2 rounded border border-purple-900/40">
                        <span className="text-slate-400">Confidence:</span>
                        <span className="text-purple-300 font-bold">
                          {selectedAlert.threat_intel_context.confidence}% ({selectedAlert.threat_intel_context.provider})
                        </span>
                      </div>
                      {selectedAlert.threat_intel_context.tags && selectedAlert.threat_intel_context.tags.length > 0 && (
                        <div className="flex flex-wrap gap-1 pt-1">
                          {selectedAlert.threat_intel_context.tags.map((t: string) => (
                            <span key={t} className="px-1.5 py-0.5 rounded text-[10px] bg-purple-950 border border-purple-800 text-purple-300">
                              #{t}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="text-[11px] text-slate-400">
                      Indicator: <span className="text-slate-200 font-semibold">{selectedAlert.source_ip || 'None'}</span> (Enrichment available)
                    </div>
                  )}

                  {selectedAlert.risk_adjustment_reason && (
                    <div className="p-2 rounded bg-slate-950/80 border border-purple-900/40 text-[10px] text-purple-200/90 leading-relaxed">
                      <span className="font-bold text-purple-400 block mb-0.5">Risk Adjustment Rationale:</span>
                      {selectedAlert.risk_adjustment_reason}
                    </div>
                  )}
                </div>
              )}

              {/* Evidence Event Payload */}
              {selectedAlert.event && (
                <div>
                  <span className="text-[11px] text-slate-500 uppercase font-bold block mb-1">
                    Normalized Event Telemetry:
                  </span>
                  <pre className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[10px] text-emerald-400 overflow-x-auto max-h-36">
                    {JSON.stringify(selectedAlert.event, null, 2)}
                  </pre>
                </div>
              )}

              {/* Analyst Notes */}
              <div>
                <span className="text-[11px] text-slate-500 uppercase font-bold block mb-1">
                  Analyst Investigation Notes:
                </span>
                <textarea
                  rows={3}
                  value={analystNotes}
                  onChange={(e) => setAnalystNotes(e.target.value)}
                  placeholder="Record investigative steps, false positive reasoning, or remediation actions..."
                  className="w-full p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500/50 text-xs font-mono"
                />
                <div className="flex justify-between items-center mt-2">
                  <button
                    onClick={handleSaveNotes}
                    disabled={savingNotes}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition cursor-pointer text-xs"
                  >
                    <Save className="h-3.5 w-3.5" />
                    <span>{savingNotes ? 'Saving...' : 'Save Notes'}</span>
                  </button>

                  <button
                    onClick={handleEscalateToIncident}
                    disabled={escalating}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800 transition cursor-pointer text-xs font-bold"
                  >
                    <Flame className="h-3.5 w-3.5" />
                    <span>{escalating ? 'Escalating...' : 'Escalate to Incident'}</span>
                  </button>
                </div>
              </div>

              {/* Metadata timestamps */}
              <div className="pt-2 border-t border-slate-800 text-[10px] text-slate-500 flex justify-between">
                <span>Created: {new Date(selectedAlert.created_at).toLocaleString()}</span>
                <span>Updated: {new Date(selectedAlert.updated_at).toLocaleString()}</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
