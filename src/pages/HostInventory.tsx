import React, { useEffect, useState } from 'react';
import {
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Search,
  RefreshCw,
  Plus,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Terminal,
  Activity,
  Cpu,
  HardDrive,
  X,
  ExternalLink,
  ChevronRight,
  Filter,
  Trash2,
  Radio,
} from 'lucide-react';
import { Host, HostCreatePayload, HostStatus } from '../types';
import {
  fetchHosts,
  registerHost,
  isolateHost,
  deleteHost,
  sendHostHeartbeat,
  fetchHostById,
} from '../services/api';
import { useRealtime } from '../services/realtime';

interface HostInventoryProps {
  onNavigateThreatIntel?: (ip: string) => void;
  onNavigateTab?: (tabId: string) => void;
}

export const HostInventory: React.FC<HostInventoryProps> = ({
  onNavigateThreatIntel,
  onNavigateTab,
}) => {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [osFilter, setOsFilter] = useState('ALL');

  // Selected Host for Details Drawer
  const [selectedHost, setSelectedHost] = useState<Host | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  // Modal States
  const [showRegisterModal, setShowRegisterModal] = useState(false);
  const [newHost, setNewHost] = useState<HostCreatePayload>({
    hostname: '',
    ip_address: '',
    operating_system: 'Windows 11 Enterprise (23H2)',
    agent_version: '1.0.0',
    status: 'ONLINE',
  });
  const [registering, setRegistering] = useState(false);
  const [registerError, setRegisterError] = useState<string | null>(null);

  // Isolation Modal
  const [isolateModalHost, setIsolateModalHost] = useState<Host | null>(null);
  const [isolateReason, setIsolateReason] = useState('Suspicious lateral movement activity detected in lab simulation.');
  const [isolating, setIsolating] = useState(false);

  const loadHosts = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await fetchHosts({
        status: statusFilter,
        os: osFilter,
        search: searchTerm,
      });
      setHosts(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load host inventory');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHosts();
  }, [statusFilter, osFilter]);

  // Real-time updates via WebSocket
  useRealtime(
    (data: any) => {
      if (['host.status', 'host_status'].includes(data.type)) {
        loadHosts();
        const hostObj = data.host || data.data;
        if (selectedHost && hostObj && hostObj.id === selectedHost.id) {
          setSelectedHost((prev) => (prev ? { ...prev, ...hostObj } : null));
        }
      }
    }
  );

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadHosts();
  };

  const handleSelectHost = async (host: Host) => {
    try {
      setLoadingDetail(true);
      setSelectedHost(host);
      const detail = await fetchHostById(host.id);
      setSelectedHost(detail);
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleRegisterHost = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newHost.hostname || !newHost.ip_address) {
      setRegisterError('Hostname and IP address are required.');
      return;
    }
    try {
      setRegistering(true);
      setRegisterError(null);
      await registerHost(newHost);
      setShowRegisterModal(false);
      setNewHost({
        hostname: '',
        ip_address: '',
        operating_system: 'Windows 11 Enterprise (23H2)',
        agent_version: '1.0.0',
        status: 'ONLINE',
      });
      await loadHosts();
    } catch (err: any) {
      setRegisterError(err.message || 'Registration failed');
    } finally {
      setRegistering(false);
    }
  };

  const handleToggleIsolate = async () => {
    if (!isolateModalHost) return;
    const shouldIsolate = isolateModalHost.status !== 'ISOLATED';
    try {
      setIsolating(true);
      const updated = await isolateHost(isolateModalHost.id, {
        isolate: shouldIsolate,
        reason: isolateReason,
      });
      setIsolateModalHost(null);
      if (selectedHost && selectedHost.id === updated.id) {
        setSelectedHost(updated);
      }
      await loadHosts();
    } catch (err: any) {
      alert(`Containment command failed: ${err.message}`);
    } finally {
      setIsolating(false);
    }
  };

  const handleTriggerHeartbeat = async (hostId: number) => {
    try {
      const updated = await sendHostHeartbeat(hostId, { status: 'ONLINE' });
      if (selectedHost && selectedHost.id === hostId) {
        setSelectedHost({ ...selectedHost, ...updated });
      }
      await loadHosts();
    } catch (err: any) {
      console.error('Heartbeat ping failed:', err);
    }
  };

  const handleDeleteHost = async (hostId: number, name: string) => {
    if (!confirm(`Are you sure you want to decommission and remove endpoint '${name}' from inventory?`)) {
      return;
    }
    try {
      await deleteHost(hostId);
      if (selectedHost && selectedHost.id === hostId) {
        setSelectedHost(null);
      }
      await loadHosts();
    } catch (err: any) {
      alert(`Decommissioning failed: ${err.message}`);
    }
  };

  const totalHosts = hosts.length;
  const onlineHosts = hosts.filter((h) => h.status === 'ONLINE').length;
  const isolatedHosts = hosts.filter((h) => h.status === 'ISOLATED').length;
  const offlineHosts = hosts.filter((h) => h.status === 'OFFLINE' || h.status === 'DEGRADED').length;

  const formatRelativeTime = (isoString: string) => {
    try {
      const diffSec = Math.round((Date.now() - new Date(isoString).getTime()) / 1000);
      if (diffSec < 15) return 'Just now';
      if (diffSec < 60) return `${diffSec}s ago`;
      if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
      if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
      return `${Math.floor(diffSec / 86400)}d ago`;
    } catch {
      return isoString;
    }
  };

  const getStatusBadge = (status: HostStatus) => {
    switch (status) {
      case 'ONLINE':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
            ONLINE
          </span>
        );
      case 'ISOLATED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-rose-500/15 text-rose-400 border border-rose-500/30">
            <ShieldAlert className="h-3 w-3" />
            ISOLATED
          </span>
        );
      case 'DEGRADED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
            DEGRADED
          </span>
        );
      case 'OFFLINE':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-slate-800 text-slate-400 border border-slate-700">
            <span className="h-1.5 w-1.5 rounded-full bg-slate-500" />
            OFFLINE
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-indigo-400">
              <Server className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-xl font-mono font-bold tracking-tight text-white flex items-center gap-2">
                Host Inventory & Endpoint Monitoring
                <span className="text-xs px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-sans font-medium">
                  Phase 6
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Real-time telemetry agent tracking, network presence, health heartbeat, and simulated containment.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={loadHosts}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 rounded-lg transition disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            Sync
          </button>
          <button
            onClick={() => setShowRegisterModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono font-medium bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg shadow-sm shadow-indigo-500/20 transition"
          >
            <Plus className="h-3.5 w-3.5" />
            Register Endpoint
          </button>
        </div>
      </div>

      {/* KPI Metric Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Total Monitored</span>
            <Server className="h-4 w-4 text-slate-500" />
          </div>
          <div className="text-2xl font-mono font-bold text-white mt-2">{totalHosts}</div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono">Endpoints in scope</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-emerald-400">Online & Active</span>
            <CheckCircle2 className="h-4 w-4 text-emerald-500" />
          </div>
          <div className="text-2xl font-mono font-bold text-emerald-400 mt-2">{onlineHosts}</div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono">Heartbeat &lt; 60s</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-rose-400">Contained / Isolated</span>
            <ShieldAlert className="h-4 w-4 text-rose-500" />
          </div>
          <div className="text-2xl font-mono font-bold text-rose-400 mt-2">{isolatedHosts}</div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono">Lab safe containment</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-amber-400">Offline / Degraded</span>
            <Clock className="h-4 w-4 text-amber-500" />
          </div>
          <div className="text-2xl font-mono font-bold text-amber-400 mt-2">{offlineHosts}</div>
          <div className="text-[11px] text-slate-500 mt-1 font-mono">Stale check-in</div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row items-center justify-between gap-3 p-3 rounded-xl bg-slate-900/50 border border-slate-800">
        <form onSubmit={handleSearchSubmit} className="flex-1 w-full flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="h-4 w-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search by hostname, FQDN, or IP address..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500/50"
            />
          </div>
          <button
            type="submit"
            className="px-3 py-1.5 text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition"
          >
            Search
          </button>
        </form>

        <div className="flex items-center gap-2 w-full md:w-auto overflow-x-auto pb-1 md:pb-0">
          <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400 whitespace-nowrap">
            <Filter className="h-3.5 w-3.5 text-slate-500" />
            Status:
          </div>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-indigo-500/50"
          >
            <option value="ALL">All Statuses</option>
            <option value="ONLINE">Online</option>
            <option value="ISOLATED">Isolated</option>
            <option value="DEGRADED">Degraded</option>
            <option value="OFFLINE">Offline</option>
          </select>

          <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400 whitespace-nowrap ml-2">
            OS:
          </div>
          <select
            value={osFilter}
            onChange={(e) => setOsFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-indigo-500/50"
          >
            <option value="ALL">All Platforms</option>
            <option value="Windows">Windows</option>
            <option value="Linux">Linux</option>
            <option value="Darwin">macOS</option>
          </select>
        </div>
      </div>

      {/* Main Host Inventory Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/40 overflow-hidden">
        {loading ? (
          <div className="py-16 text-center">
            <RefreshCw className="h-6 w-6 text-indigo-400 animate-spin mx-auto mb-2" />
            <p className="text-xs font-mono text-slate-400">Loading endpoint inventory...</p>
          </div>
        ) : error ? (
          <div className="py-12 text-center text-rose-400 text-xs font-mono">
            <AlertTriangle className="h-6 w-6 mx-auto mb-2 text-rose-500" />
            {error}
          </div>
        ) : hosts.length === 0 ? (
          <div className="py-16 text-center text-slate-500 text-xs font-mono">
            No endpoints matched the query criteria. Register an agent to begin monitoring.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase text-[11px] tracking-wider">
                <tr>
                  <th className="py-3 px-4">Endpoint Hostname</th>
                  <th className="py-3 px-4">IP Address</th>
                  <th className="py-3 px-4">Platform &amp; OS</th>
                  <th className="py-3 px-4">Agent Ver</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Last Check-In</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {hosts.map((host) => {
                  const isSelected = selectedHost?.id === host.id;
                  const isWindows = host.operating_system.toLowerCase().includes('windows');
                  return (
                    <tr
                      key={host.id}
                      onClick={() => handleSelectHost(host)}
                      className={`hover:bg-slate-800/40 cursor-pointer transition ${
                        isSelected ? 'bg-indigo-950/30 border-l-2 border-indigo-500' : ''
                      }`}
                    >
                      <td className="py-3 px-4 font-semibold text-white flex items-center gap-2">
                        <Server
                          className={`h-4 w-4 ${isWindows ? 'text-cyan-400' : 'text-amber-400'}`}
                        />
                        <span>{host.hostname}</span>
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            if (onNavigateThreatIntel) onNavigateThreatIntel(host.ip_address);
                          }}
                          className="hover:text-cyan-400 hover:underline inline-flex items-center gap-1"
                          title="Inspect in Threat Intelligence"
                        >
                          {host.ip_address}
                        </button>
                      </td>
                      <td className="py-3 px-4 text-slate-300">{host.operating_system}</td>
                      <td className="py-3 px-4 text-slate-400">v{host.agent_version}</td>
                      <td className="py-3 px-4">{getStatusBadge(host.status)}</td>
                      <td className="py-3 px-4 text-slate-400">{formatRelativeTime(host.last_seen)}</td>
                      <td className="py-3 px-4 text-right" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => setIsolateModalHost(host)}
                            className={`px-2.5 py-1 rounded text-[11px] font-mono border transition ${
                              host.status === 'ISOLATED'
                                ? 'bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                                : 'bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border-rose-500/30'
                            }`}
                            title={host.status === 'ISOLATED' ? 'Restore connectivity' : 'Simulate isolation'}
                          >
                            {host.status === 'ISOLATED' ? 'Unisolate' : 'Isolate'}
                          </button>
                          <button
                            onClick={() => handleDeleteHost(host.id, host.hostname)}
                            className="p-1 rounded text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 transition"
                            title="Decommission Endpoint"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Selected Host Details Drawer / Modal */}
      {selectedHost && (
        <div className="rounded-xl border border-indigo-500/30 bg-slate-900/80 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-indigo-500/20 text-indigo-400 border border-indigo-500/40">
                <Server className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-base font-mono font-bold text-white flex items-center gap-2">
                  {selectedHost.hostname}
                  {getStatusBadge(selectedHost.status)}
                </h3>
                <p className="text-xs font-mono text-slate-400 mt-0.5">
                  IP: <span className="text-slate-200">{selectedHost.ip_address}</span> • OS:{' '}
                  <span className="text-slate-200">{selectedHost.operating_system}</span> • Agent:{' '}
                  <span className="text-slate-200">v{selectedHost.agent_version}</span>
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => handleTriggerHeartbeat(selectedHost.id)}
                className="px-2.5 py-1 text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 transition"
                title="Send synthetic agent check-in ping"
              >
                Ping Heartbeat
              </button>
              <button
                onClick={() => setIsolateModalHost(selectedHost)}
                className={`px-3 py-1 text-xs font-mono rounded border transition ${
                  selectedHost.status === 'ISOLATED'
                    ? 'bg-emerald-600 hover:bg-emerald-500 text-white border-emerald-500'
                    : 'bg-rose-600 hover:bg-rose-500 text-white border-rose-500'
                }`}
              >
                {selectedHost.status === 'ISOLATED' ? 'Restore Network' : 'Isolate Host (Lab Mode)'}
              </button>
              <button
                onClick={() => setSelectedHost(null)}
                className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          </div>

          {/* Host Metrics & Security Activity */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Endpoint Risk</div>
              <div className="text-2xl font-mono font-bold text-amber-400 mt-1">
                {selectedHost.calculated_risk || 20}/100
              </div>
              <p className="text-[11px] text-slate-500 mt-0.5 font-mono">
                {selectedHost.status === 'ISOLATED' ? 'Elevated due to containment' : 'Calculated from correlated alerts'}
              </p>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Telemetry Ingested</div>
              <div className="text-2xl font-mono font-bold text-white mt-1">
                {selectedHost.event_count || selectedHost.recent_events?.length || 0}
              </div>
              <p className="text-[11px] text-slate-500 mt-0.5 font-mono">Recent security events logged</p>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Active Alerts</div>
              <div className="text-2xl font-mono font-bold text-rose-400 mt-1">
                {selectedHost.alert_count || selectedHost.recent_alerts?.length || 0}
              </div>
              <p className="text-[11px] text-slate-500 mt-0.5 font-mono">Detections targeting host</p>
            </div>
          </div>

          {/* Recent Events & Alerts Tabs / Lists */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Recent Events */}
            <div className="space-y-2">
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Terminal className="h-3.5 w-3.5 text-indigo-400" />
                Recent Endpoint Telemetry
              </h4>
              <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                {selectedHost.recent_events && selectedHost.recent_events.length > 0 ? (
                  selectedHost.recent_events.map((evt, idx) => (
                    <div
                      key={idx}
                      className="p-2 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono flex items-center justify-between"
                    >
                      <div className="truncate pr-2">
                        <span className="text-indigo-400 font-semibold">{evt.event_type}</span>
                        <span className="text-slate-400 ml-2">{evt.message}</span>
                      </div>
                      <span className="text-slate-500 whitespace-nowrap">{formatRelativeTime(evt.timestamp)}</span>
                    </div>
                  ))
                ) : (
                  <div className="py-4 text-center text-slate-500 text-xs font-mono bg-slate-950 rounded border border-slate-800">
                    No recent events logged for this host.
                  </div>
                )}
              </div>
            </div>

            {/* Correlated Alerts */}
            <div className="space-y-2">
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <ShieldAlert className="h-3.5 w-3.5 text-rose-400" />
                Correlated Security Alerts
              </h4>
              <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                {selectedHost.recent_alerts && selectedHost.recent_alerts.length > 0 ? (
                  selectedHost.recent_alerts.map((al, idx) => (
                    <div
                      key={idx}
                      className="p-2 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono flex items-center justify-between"
                    >
                      <div className="truncate pr-2">
                        <span className="text-rose-400 font-semibold">[{al.severity}]</span>
                        <span className="text-slate-200 ml-2">{al.title}</span>
                      </div>
                      <span className="text-amber-400 font-bold ml-2">Risk: {al.risk_score}</span>
                    </div>
                  ))
                ) : (
                  <div className="py-4 text-center text-slate-500 text-xs font-mono bg-slate-950 rounded border border-slate-800">
                    No active detections on this endpoint.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Registration Modal */}
      {showRegisterModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-mono font-bold text-white flex items-center gap-2">
                <Plus className="h-4 w-4 text-indigo-400" />
                Register New Host Endpoint
              </h3>
              <button
                onClick={() => setShowRegisterModal(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {registerError && (
              <div className="p-2.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-mono">
                {registerError}
              </div>
            )}

            <form onSubmit={handleRegisterHost} className="space-y-3 font-mono text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Hostname / FQDN</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. WIN-DC02.CORP.LOCAL"
                  value={newHost.hostname}
                  onChange={(e) => setNewHost({ ...newHost, hostname: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Network IP Address</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 10.0.0.45"
                  value={newHost.ip_address}
                  onChange={(e) => setNewHost({ ...newHost, ip_address: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Operating System</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Windows Server 2022 / Windows 11"
                  value={newHost.operating_system}
                  onChange={(e) => setNewHost({ ...newHost, operating_system: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Agent Version</label>
                <input
                  type="text"
                  placeholder="1.0.0"
                  value={newHost.agent_version}
                  onChange={(e) => setNewHost({ ...newHost, agent_version: e.target.value })}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="pt-2 flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowRegisterModal(false)}
                  className="px-3 py-1.5 text-xs text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={registering}
                  className="px-4 py-1.5 text-xs bg-indigo-600 hover:bg-indigo-500 text-white rounded font-semibold transition disabled:opacity-50"
                >
                  {registering ? 'Registering...' : 'Register Endpoint'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Simulated Isolation Modal */}
      {isolateModalHost && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center gap-3">
              <div
                className={`p-2 rounded-lg ${
                  isolateModalHost.status === 'ISOLATED'
                    ? 'bg-emerald-500/20 text-emerald-400'
                    : 'bg-rose-500/20 text-rose-400'
                }`}
              >
                <ShieldAlert className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-sm font-mono font-bold text-white">
                  {isolateModalHost.status === 'ISOLATED'
                    ? 'Restore Network Connectivity'
                    : 'Execute Simulated Containment'}
                </h3>
                <p className="text-xs font-mono text-slate-400">
                  Target: {isolateModalHost.hostname} ({isolateModalHost.ip_address})
                </p>
              </div>
            </div>

            <div className="p-3 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-mono">
              ⚠️ <strong>Safe Lab Simulation:</strong> In SentinelX default configuration, all isolation actions execute in simulated sandbox mode. No real firewall modifications are applied to physical devices.
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-400 mb-1">
                Containment Justification / Reason:
              </label>
              <textarea
                rows={2}
                value={isolateReason}
                onChange={(e) => setIsolateReason(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded text-xs font-mono text-slate-200 focus:outline-none focus:border-rose-500"
              />
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setIsolateModalHost(null)}
                className="px-3 py-1.5 text-xs font-mono text-slate-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleToggleIsolate}
                disabled={isolating}
                className={`px-4 py-1.5 text-xs font-mono font-semibold rounded text-white transition ${
                  isolateModalHost.status === 'ISOLATED'
                    ? 'bg-emerald-600 hover:bg-emerald-500'
                    : 'bg-rose-600 hover:bg-rose-500'
                }`}
              >
                {isolating
                  ? 'Executing...'
                  : isolateModalHost.status === 'ISOLATED'
                  ? 'Confirm Reconnection'
                  : 'Confirm Isolation'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
