import React, { useState, useEffect, useCallback } from 'react';
import {
  Radio,
  Search,
  Filter,
  RefreshCw,
  Clock,
  Eye,
  X,
  Play,
  CheckCircle2,
} from 'lucide-react';
import { SecurityEvent, AlertSeverity } from '../types';
import { fetchEvents, ingestEvent } from '../services/api';
import { SeverityBadge } from '../components/SeverityBadge';
import { useRealtime } from '../services/realtime';

export const EventTelemetry: React.FC = () => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [notification, setNotification] = useState<string | null>(null);

  // Filters
  const [search, setSearch] = useState('');
  const [eventTypeFilter, setEventTypeFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [sourceIpFilter, setSourceIpFilter] = useState('');
  const [destIpFilter, setDestIpFilter] = useState('');
  const [hostnameFilter, setHostnameFilter] = useState('');

  // Manual ingest form toggle
  const [showIngestForm, setShowIngestForm] = useState(false);
  const [ingestEventType, setIngestEventType] = useState('port_scan');
  const [ingestSrcIp, setIngestSrcIp] = useState('192.0.2.77');
  const [ingestDstIp, setIngestDstIp] = useState('10.0.0.12');
  const [ingestDstPort, setIngestDstPort] = useState(22);
  const [ingestSeverity, setIngestSeverity] = useState('HIGH');
  const [ingestMsg, setIngestMsg] = useState('Port probe detected on destination 22');
  const [ingesting, setIngesting] = useState(false);

  const loadEvents = useCallback(async () => {
    try {
      const data = await fetchEvents({
        event_type: eventTypeFilter,
        severity: severityFilter,
        source_ip: sourceIpFilter || undefined,
        destination_ip: destIpFilter || undefined,
        hostname: hostnameFilter || undefined,
        search: search || undefined,
        limit: 100,
      });
      setEvents(data);
    } catch (err) {
      console.error('Failed to load events:', err);
    } finally {
      setLoading(false);
    }
  }, [eventTypeFilter, severityFilter, sourceIpFilter, destIpFilter, hostnameFilter, search]);

  // Real-time listener for incoming events via WebSocket
  useRealtime(
    useCallback((data: any) => {
      if (['event.created', 'alert.created', 'new_event', 'new_alert'].includes(data.type)) {
        loadEvents();
      }
    }, [loadEvents])
  );

  useEffect(() => {
    loadEvents();
  }, [loadEvents]);

  const handleManualIngest = async (e: React.FormEvent) => {
    e.preventDefault();
    setIngesting(true);
    try {
      const res = await ingestEvent({
        event_type: ingestEventType,
        source: 'telemetry-agent',
        source_ip: ingestSrcIp,
        destination_ip: ingestDstIp,
        destination_port: Number(ingestDstPort),
        protocol: 'TCP',
        severity: ingestSeverity,
        message: ingestMsg,
      });
      setNotification(`Ingested event ${res.event_ids[0]}. Generated alerts: ${res.generated_alerts.length}`);
      setShowIngestForm(false);
      loadEvents();
      setTimeout(() => setNotification(null), 4000);
    } catch (err: any) {
      setNotification(`Ingestion failed: ${err.message}`);
    } finally {
      setIngesting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Radio className="h-5 w-5 text-emerald-400" />
            <h2 className="text-lg font-bold font-mono text-slate-100 uppercase tracking-wide">
              Security Event Telemetry & Logs
            </h2>
            <span className="rounded bg-slate-800 px-2 py-0.5 text-xs font-mono text-slate-300">
              {events.length} Telemetry Events
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Indexed security telemetry from network sensors, Linux/Windows agents, and WAF endpoints
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowIngestForm(!showIngestForm)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-bold transition cursor-pointer"
          >
            <Play className="h-3.5 w-3.5" />
            <span>Ingest Test Event</span>
          </button>

          <button
            onClick={loadEvents}
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

      {/* Manual Ingest Drawer */}
      {showIngestForm && (
        <div className="rounded-xl border border-emerald-800/80 bg-slate-900/90 p-5 font-mono text-xs space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <span className="font-bold text-emerald-400 uppercase tracking-wider">
              Inject Telemetry Event into Detection Engine
            </span>
            <button onClick={() => setShowIngestForm(false)} className="text-slate-400 hover:text-slate-200 cursor-pointer">
              <X className="h-4 w-4" />
            </button>
          </div>

          <form onSubmit={handleManualIngest} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <label className="block text-slate-400 mb-1">Event Type:</label>
              <select
                value={ingestEventType}
                onChange={(e) => setIngestEventType(e.target.value)}
                className="w-full p-2 rounded bg-slate-950 border border-slate-800 text-slate-200"
              >
                <option value="port_scan">port_scan (T1046)</option>
                <option value="authentication_failure">authentication_failure (T1110.001)</option>
                <option value="http_request">http_request (T1190)</option>
                <option value="syn_flood_burst">syn_flood_burst (T1498)</option>
                <option value="privilege_escalation">privilege_escalation (T1068)</option>
                <option value="impossible_travel">impossible_travel (T1078)</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Source IP:</label>
              <input
                type="text"
                value={ingestSrcIp}
                onChange={(e) => setIngestSrcIp(e.target.value)}
                className="w-full p-2 rounded bg-slate-950 border border-slate-800 text-slate-200"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Destination IP:</label>
              <input
                type="text"
                value={ingestDstIp}
                onChange={(e) => setIngestDstIp(e.target.value)}
                className="w-full p-2 rounded bg-slate-950 border border-slate-800 text-slate-200"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Severity:</label>
              <select
                value={ingestSeverity}
                onChange={(e) => setIngestSeverity(e.target.value)}
                className="w-full p-2 rounded bg-slate-950 border border-slate-800 text-slate-200"
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
                <option value="INFORMATIONAL">INFORMATIONAL</option>
              </select>
            </div>

            <div className="sm:col-span-3">
              <label className="block text-slate-400 mb-1">Message:</label>
              <input
                type="text"
                value={ingestMsg}
                onChange={(e) => setIngestMsg(e.target.value)}
                className="w-full p-2 rounded bg-slate-950 border border-slate-800 text-slate-200"
              />
            </div>

            <div className="flex items-end">
              <button
                type="submit"
                disabled={ingesting}
                className="w-full p-2 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-bold transition cursor-pointer disabled:opacity-50"
              >
                {ingesting ? 'Processing...' : 'Send Event'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Filter Toolbar */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 font-mono text-xs space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search message, ID..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 placeholder:text-slate-600 focus:outline-none"
            />
          </div>

          <select
            value={eventTypeFilter}
            onChange={(e) => setEventTypeFilter(e.target.value)}
            className="px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none"
          >
            <option value="ALL">All Event Types</option>
            <option value="port_scan">port_scan</option>
            <option value="authentication_failure">authentication_failure</option>
            <option value="http_request">http_request</option>
            <option value="syn_flood_burst">syn_flood_burst</option>
            <option value="process_exec">process_exec</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
            <option value="INFORMATIONAL">INFORMATIONAL</option>
          </select>

          <input
            type="text"
            placeholder="Source IP..."
            value={sourceIpFilter}
            onChange={(e) => setSourceIpFilter(e.target.value)}
            className="px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 placeholder:text-slate-600 focus:outline-none"
          />

          <input
            type="text"
            placeholder="Hostname..."
            value={hostnameFilter}
            onChange={(e) => setHostnameFilter(e.target.value)}
            className="px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 placeholder:text-slate-600 focus:outline-none"
          />
        </div>
      </div>

      {/* Events Table & Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className={`space-y-4 ${selectedEvent ? 'lg:col-span-7' : 'lg:col-span-12'}`}>
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden font-mono text-xs">
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead className="bg-slate-950 border-b border-slate-800 text-slate-400 text-[11px]">
                  <tr>
                    <th className="py-3 px-4">SEVERITY</th>
                    <th className="py-3 px-4">TIMESTAMP</th>
                    <th className="py-3 px-4">EVENT TYPE</th>
                    <th className="py-3 px-4">SOURCE → DESTINATION</th>
                    <th className="py-3 px-4">MESSAGE</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {events.map((ev) => {
                    const isSelected = selectedEvent?.id === ev.id;
                    return (
                      <tr
                        key={ev.id}
                        onClick={() => setSelectedEvent(ev)}
                        className={`hover:bg-slate-800/50 cursor-pointer transition ${
                          isSelected ? 'bg-emerald-950/20 border-l-2 border-emerald-500' : ''
                        }`}
                      >
                        <td className="py-3 px-4">
                          <SeverityBadge severity={ev.severity} size="sm" />
                        </td>
                        <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                          {new Date(ev.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="py-3 px-4 text-cyan-400 font-semibold">{ev.event_type}</td>
                        <td className="py-3 px-4 text-slate-300">
                          {ev.source_ip || 'host'} → {ev.destination_ip || 'dest'}
                        </td>
                        <td className="py-3 px-4 text-slate-400 max-w-[240px] truncate" title={ev.message}>
                          {ev.message}
                        </td>
                      </tr>
                    );
                  })}
                  {events.length === 0 && (
                    <tr>
                      <td colSpan={5} className="py-8 text-center text-slate-500">
                        No telemetry events match query filters.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Selected Event JSON Inspector */}
        {selectedEvent && (
          <div className="lg:col-span-5 space-y-4 font-mono text-xs">
            <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 space-y-4">
              <div className="flex items-start justify-between border-b border-slate-800 pb-3">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-slate-400 font-bold">{selectedEvent.event_id}</span>
                    <SeverityBadge severity={selectedEvent.severity} size="sm" />
                  </div>
                  <h3 className="text-sm font-bold text-slate-100">{selectedEvent.event_type}</h3>
                </div>
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="text-slate-400 hover:text-slate-200 cursor-pointer"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="grid grid-cols-2 gap-3 bg-slate-950 p-3 rounded border border-slate-800">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase">Source</span>
                  <div className="text-slate-200 mt-0.5">
                    {selectedEvent.source_ip || 'N/A'}:{selectedEvent.source_port || ''}
                  </div>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 uppercase">Destination</span>
                  <div className="text-slate-200 mt-0.5">
                    {selectedEvent.destination_ip || 'N/A'}:{selectedEvent.destination_port || ''}
                  </div>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 uppercase">Hostname</span>
                  <div className="text-slate-200 mt-0.5">{selectedEvent.hostname || 'None'}</div>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 uppercase">Protocol</span>
                  <div className="text-slate-200 mt-0.5">{selectedEvent.protocol || 'TCP'}</div>
                </div>
              </div>

              <div>
                <span className="text-[10px] text-slate-500 uppercase font-bold block mb-1">Raw Payload:</span>
                <pre className="p-3 rounded bg-slate-950 border border-slate-800 text-[10px] text-emerald-400 overflow-x-auto max-h-56">
                  {JSON.stringify(selectedEvent, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
