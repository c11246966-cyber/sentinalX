import React, { useState, useEffect, useCallback } from 'react';
import {
  Flame,
  Plus,
  Shield,
  CheckCircle2,
  Clock,
  User,
  Layers,
  ArrowRight,
  FileText,
  Save,
  AlertTriangle,
  X,
  RefreshCw,
} from 'lucide-react';
import { Incident, Alert, IncidentStatus, AlertSeverity } from '../types';
import { fetchIncidents, fetchIncidentById, createIncident, updateIncident, fetchAlerts } from '../services/api';
import { SeverityBadge } from '../components/SeverityBadge';
import { RiskScoreMeter } from '../components/RiskScoreMeter';
import { useRealtime } from '../services/realtime';

interface IncidentManagementProps {
  initialSelectedIncident?: Incident | null;
  onClearSelectedIncident?: () => void;
  onNavigateTab?: (tab: string) => void;
}

export const IncidentManagement: React.FC<IncidentManagementProps> = ({
  initialSelectedIncident,
  onClearSelectedIncident,
  onNavigateTab,
}) => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(initialSelectedIncident || null);
  const [availableAlerts, setAvailableAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [notification, setNotification] = useState<string | null>(null);

  // Edit fields for selected incident
  const [analystNotes, setAnalystNotes] = useState('');
  const [savingNotes, setSavingNotes] = useState(false);

  // New incident form state
  const [newTitle, setNewTitle] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newSeverity, setNewSeverity] = useState<AlertSeverity>('HIGH');
  const [newRiskScore, setNewRiskScore] = useState(80);
  const [selectedAlertIds, setSelectedAlertIds] = useState<number[]>([]);
  const [newAssignee, setNewAssignee] = useState<number>(2);

  const loadIncidents = useCallback(async () => {
    try {
      const data = await fetchIncidents();
      setIncidents(data);
    } catch (err) {
      console.error('Failed to load incidents:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadAvailableAlerts = useCallback(async () => {
    try {
      const data = await fetchAlerts({ status: 'ALL' });
      setAvailableAlerts(data);
    } catch (err) {
      console.debug('Failed to load alerts for incident linking:', err);
    }
  }, []);

  // Real-time updates via WebSocket
  useRealtime(
    useCallback((data: any) => {
      if ([
        'incident.created',
        'incident.updated',
        'alert.created',
        'new_incident',
        'incident_updated',
        'new_alert',
      ].includes(data.type)) {
        loadIncidents();
        const incObj = data.incident || data.data;
        if (selectedIncident && incObj && incObj.id === selectedIncident.id) {
          handleSelectIncident(selectedIncident);
        }
      }
    }, [loadIncidents, selectedIncident])
  );

  useEffect(() => {
    loadIncidents();
    loadAvailableAlerts();
  }, [loadIncidents, loadAvailableAlerts]);

  useEffect(() => {
    if (initialSelectedIncident) {
      handleSelectIncident(initialSelectedIncident);
    }
  }, [initialSelectedIncident]);

  const handleSelectIncident = async (inc: Incident) => {
    try {
      const detail = await fetchIncidentById(inc.id);
      setSelectedIncident(detail);
      setAnalystNotes(detail.analyst_notes || '');
    } catch {
      setSelectedIncident(inc);
      setAnalystNotes(inc.analyst_notes || '');
    }
  };

  const handleStatusChange = async (newStatus: IncidentStatus) => {
    if (!selectedIncident) return;
    try {
      const updated = await updateIncident(selectedIncident.id, { status: newStatus });
      setSelectedIncident((prev) => (prev ? { ...prev, ...updated } : updated));
      setIncidents((prev) => prev.map((i) => (i.id === updated.id ? { ...i, status: updated.status } : i)));
      setNotification(`Incident #${selectedIncident.id} status updated to ${newStatus}`);
      setTimeout(() => setNotification(null), 3000);
    } catch (err: any) {
      setNotification(`Status update failed: ${err.message}`);
    }
  };

  const handleSeverityChange = async (newSev: AlertSeverity) => {
    if (!selectedIncident) return;
    try {
      const updated = await updateIncident(selectedIncident.id, { severity: newSev });
      setSelectedIncident((prev) => (prev ? { ...prev, ...updated } : updated));
      setIncidents((prev) => prev.map((i) => (i.id === updated.id ? { ...i, severity: updated.severity } : i)));
      setNotification(`Incident #${selectedIncident.id} severity changed to ${newSev}`);
      setTimeout(() => setNotification(null), 3000);
    } catch (err: any) {
      setNotification(`Severity update failed: ${err.message}`);
    }
  };

  const handleAssigneeChange = async (userId: number) => {
    if (!selectedIncident) return;
    try {
      const updated = await updateIncident(selectedIncident.id, { assigned_to: userId });
      const assigneeNames: Record<number, string> = { 1: 'admin', 2: 'analyst', 3: 'viewer' };
      setSelectedIncident((prev) => (prev ? { ...prev, assigned_to: userId, assignee_name: assigneeNames[userId] } : null));
      setNotification(`Incident #${selectedIncident.id} assigned to ${assigneeNames[userId] || 'user'}`);
      setTimeout(() => setNotification(null), 3000);
    } catch (err: any) {
      setNotification(`Assignment failed: ${err.message}`);
    }
  };

  const handleSaveNotes = async () => {
    if (!selectedIncident) return;
    setSavingNotes(true);
    try {
      const updated = await updateIncident(selectedIncident.id, { analyst_notes: analystNotes });
      setSelectedIncident((prev) => (prev ? { ...prev, analyst_notes: updated.analyst_notes } : null));
      setNotification('Incident investigation notes recorded.');
      setTimeout(() => setNotification(null), 3000);
    } catch (err: any) {
      setNotification(`Error: ${err.message}`);
    } finally {
      setSavingNotes(false);
    }
  };

  const handleCreateIncidentSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;

    try {
      const created = await createIncident({
        title: newTitle,
        description: newDesc,
        severity: newSeverity,
        risk_score: newRiskScore,
        alert_ids: selectedAlertIds,
        assigned_to: newAssignee,
      });

      setNotification(`Declared new incident: ${created.title}`);
      setShowCreateModal(false);
      setNewTitle('');
      setNewDesc('');
      setSelectedAlertIds([]);
      loadIncidents();
      handleSelectIncident(created);
    } catch (err: any) {
      setNotification(`Incident creation failed: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Flame className="h-5 w-5 text-rose-500" />
            <h2 className="text-lg font-bold font-mono text-slate-100 uppercase tracking-wide">
              Security Incident Operations
            </h2>
            <span className="rounded bg-rose-950/80 border border-rose-800 px-2 py-0.5 text-xs font-mono text-rose-300">
              {incidents.length} Active Records
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Aggregated multi-alert correlation clusters, containment lifecycles, and analyst containment tracking
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              loadAvailableAlerts();
              setShowCreateModal(true);
            }}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-bold transition cursor-pointer"
          >
            <Plus className="h-4 w-4" />
            <span>Declare Incident</span>
          </button>

          <button
            onClick={loadIncidents}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-mono text-xs cursor-pointer"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {notification && (
        <div className="rounded border border-emerald-800 bg-emerald-950/80 p-3 text-xs font-mono text-emerald-300 flex items-center justify-between">
          <span>{notification}</span>
          <button onClick={() => setNotification(null)} className="cursor-pointer">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Main Grid: Incident List + Selected Detail Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Incident List (7 cols or full) */}
        <div className={`space-y-4 ${selectedIncident ? 'lg:col-span-6' : 'lg:col-span-12'}`}>
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden font-mono text-xs">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <span className="font-bold text-slate-300 uppercase tracking-wider">Active Incident Queue</span>
              <span className="text-[11px] text-slate-500">{incidents.length} Declared</span>
            </div>

            <div className="divide-y divide-slate-800/60">
              {incidents.map((inc) => {
                const isSelected = selectedIncident?.id === inc.id;
                return (
                  <div
                    key={inc.id}
                    onClick={() => handleSelectIncident(inc)}
                    className={`p-4 hover:bg-slate-800/50 cursor-pointer transition ${
                      isSelected ? 'bg-rose-950/20 border-l-2 border-rose-500' : ''
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-200 text-xs">INC-{inc.id}</span>
                        <SeverityBadge severity={inc.severity} size="sm" />
                      </div>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${
                          inc.status === 'NEW'
                            ? 'bg-amber-950/60 text-amber-300 border-amber-800'
                            : inc.status === 'INVESTIGATING'
                            ? 'bg-blue-950/60 text-blue-300 border-blue-800'
                            : inc.status === 'CONTAINED'
                            ? 'bg-purple-950/60 text-purple-300 border-purple-800'
                            : inc.status === 'RESOLVED'
                            ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800'
                            : 'bg-slate-900 text-slate-400 border-slate-700'
                        }`}
                      >
                        {inc.status}
                      </span>
                    </div>

                    <h4 className="font-bold text-slate-100 text-xs mb-1">{inc.title}</h4>
                    <p className="text-slate-400 text-xs line-clamp-2 mb-2">{inc.description}</p>

                    <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1">
                      <div className="flex items-center gap-3">
                        <span className="text-cyan-400 font-semibold">{inc.alert_count || 0} Correlated Alerts</span>
                        <span>Assignee: {inc.assignee_name || (inc.assigned_to ? `User #${inc.assigned_to}` : 'Unassigned')}</span>
                      </div>
                      <RiskScoreMeter score={inc.risk_score} />
                    </div>
                  </div>
                );
              })}

              {incidents.length === 0 && (
                <div className="p-8 text-center text-slate-500">
                  No active security incidents recorded in the environment.
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Selected Incident Detail Inspector (6 cols) */}
        {selectedIncident && (
          <div className="lg:col-span-6 space-y-4 font-mono text-xs">
            <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 space-y-5">
              {/* Header */}
              <div className="flex items-start justify-between border-b border-slate-800 pb-3">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-slate-400 font-bold">INCIDENT #{selectedIncident.id}</span>
                    <SeverityBadge severity={selectedIncident.severity} size="sm" />
                  </div>
                  <h3 className="text-sm font-bold text-slate-100">{selectedIncident.title}</h3>
                </div>
                <button
                  onClick={() => setSelectedIncident(null)}
                  className="text-slate-400 hover:text-slate-200 cursor-pointer p-1"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              {/* Status & Severity Controls */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1.5">
                    Lifecycle Status:
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {(['NEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED'] as IncidentStatus[]).map(
                      (st) => (
                        <button
                          key={st}
                          onClick={() => handleStatusChange(st)}
                          className={`px-2 py-0.5 rounded text-[10px] font-bold border transition cursor-pointer ${
                            selectedIncident.status === st
                              ? 'bg-rose-500/20 text-rose-300 border-rose-500'
                              : 'bg-slate-950 text-slate-400 border-slate-800 hover:border-slate-700'
                          }`}
                        >
                          {st}
                        </button>
                      )
                    )}
                  </div>
                </div>

                <div>
                  <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1.5">
                    Assignee:
                  </span>
                  <select
                    value={selectedIncident.assigned_to || 2}
                    onChange={(e) => handleAssigneeChange(parseInt(e.target.value, 10))}
                    className="w-full px-2.5 py-1 rounded bg-slate-950 border border-slate-800 text-slate-200 text-xs"
                  >
                    <option value={1}>Admin (Security Lead)</option>
                    <option value={2}>Analyst (SOC Tier 2)</option>
                    <option value={3}>Viewer (Auditor)</option>
                  </select>
                </div>
              </div>

              {/* Description */}
              <div>
                <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">
                  Incident Synthesis & Root Cause:
                </span>
                <p className="p-3 rounded bg-slate-950 border border-slate-800 text-slate-300 text-xs leading-relaxed">
                  {selectedIncident.description}
                </p>
              </div>

              {/* Correlated Alerts */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] text-slate-500 uppercase font-bold">
                    Correlated Alerts ({selectedIncident.alerts?.length || 0})
                  </span>
                  <button
                    onClick={() => onNavigateTab && onNavigateTab('alerts')}
                    className="text-[10px] text-emerald-400 hover:underline"
                  >
                    Open in Triage
                  </button>
                </div>

                <div className="space-y-2 max-h-44 overflow-y-auto pr-1">
                  {selectedIncident.alerts?.map((al) => (
                    <div
                      key={al.id}
                      className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between"
                    >
                      <div>
                        <div className="flex items-center gap-1.5">
                          <SeverityBadge severity={al.severity} size="sm" />
                          <span className="font-semibold text-slate-200">{al.title}</span>
                        </div>
                        <div className="text-[10px] text-slate-500 mt-0.5">
                          {al.source_ip || 'Src'} → {al.destination_ip || 'Dst'} • Technique: {al.mitre_technique || 'N/A'}
                        </div>
                      </div>
                      <RiskScoreMeter score={al.risk_score} />
                    </div>
                  ))}

                  {(!selectedIncident.alerts || selectedIncident.alerts.length === 0) && (
                    <div className="p-3 text-center text-slate-500 text-[11px] bg-slate-950 rounded border border-slate-800">
                      No alerts directly linked to this incident cluster yet.
                    </div>
                  )}
                </div>
              </div>

              {/* Analyst Notes */}
              <div>
                <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">
                  Incident Action Plan & Containment Notes:
                </span>
                <textarea
                  rows={3}
                  value={analystNotes}
                  onChange={(e) => setAnalystNotes(e.target.value)}
                  placeholder="Document mitigation steps, firewall blocks, or remediation verification..."
                  className="w-full p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-rose-500/50 text-xs font-mono"
                />
                <div className="flex justify-end mt-2">
                  <button
                    onClick={handleSaveNotes}
                    disabled={savingNotes}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition cursor-pointer text-xs"
                  >
                    <Save className="h-3.5 w-3.5" />
                    <span>{savingNotes ? 'Saving...' : 'Update Notes'}</span>
                  </button>
                </div>
              </div>

              {/* Timeline Metadata */}
              <div className="pt-2 border-t border-slate-800 text-[10px] text-slate-500 flex justify-between">
                <span>Declared: {new Date(selectedIncident.created_at).toLocaleString()}</span>
                <span>
                  {selectedIncident.resolved_at
                    ? `Resolved: ${new Date(selectedIncident.resolved_at).toLocaleString()}`
                    : `Last Active: ${new Date(selectedIncident.updated_at).toLocaleString()}`}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Declare Incident Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-xl rounded-xl border border-slate-800 bg-slate-900 p-6 font-mono text-xs space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Flame className="h-5 w-5 text-rose-500" />
                <h3 className="text-sm font-bold text-slate-100 uppercase">
                  Declare Security Incident
                </h3>
              </div>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-slate-200 cursor-pointer"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <form onSubmit={handleCreateIncidentSubmit} className="space-y-4">
              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Incident Title:</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Distributed Credential Brute Force & Perimeter Probe"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  className="w-full p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-rose-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1 font-semibold">Description & Findings:</label>
                <textarea
                  rows={3}
                  required
                  placeholder="Summarize the threat attack vector, impact on assets, and initial indicators..."
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  className="w-full p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-rose-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1 font-semibold">Severity:</label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value as AlertSeverity)}
                    className="w-full p-2 rounded bg-slate-950 border border-slate-800 text-slate-200"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 font-semibold">Risk Score (0-100):</label>
                  <input
                    type="number"
                    min={0}
                    max={100}
                    value={newRiskScore}
                    onChange={(e) => setNewRiskScore(parseInt(e.target.value, 10))}
                    className="w-full p-2 rounded bg-slate-950 border border-slate-800 text-slate-200"
                  >
                  </input>
                </div>
              </div>

              {/* Alert selection checklist */}
              <div>
                <label className="block text-slate-400 mb-1 font-semibold">
                  Link Active Alerts ({selectedAlertIds.length} selected):
                </label>
                <div className="max-h-36 overflow-y-auto space-y-1.5 p-2 rounded bg-slate-950 border border-slate-800">
                  {availableAlerts.map((a) => (
                    <label
                      key={a.id}
                      className="flex items-center gap-2 p-1.5 rounded hover:bg-slate-900 cursor-pointer"
                    >
                      <input
                        type="checkbox"
                        checked={selectedAlertIds.includes(a.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedAlertIds([...selectedAlertIds, a.id]);
                          } else {
                            setSelectedAlertIds(selectedAlertIds.filter((id) => id !== a.id));
                          }
                        }}
                        className="rounded border-slate-800"
                      />
                      <SeverityBadge severity={a.severity} size="sm" />
                      <span className="text-slate-300 truncate">{a.title}</span>
                    </label>
                  ))}
                  {availableAlerts.length === 0 && (
                    <div className="text-slate-500 text-center py-2">No alerts available to link.</div>
                  )}
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded bg-rose-600 hover:bg-rose-500 text-white font-bold transition cursor-pointer"
                >
                  Create Incident
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
