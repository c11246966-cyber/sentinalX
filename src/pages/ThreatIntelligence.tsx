import React, { useState, useEffect, useCallback } from 'react';
import {
  Globe2,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Search,
  Filter,
  RefreshCw,
  ExternalLink,
  Cpu,
  Layers,
  Flame,
  CheckCircle2,
  XCircle,
  Clock,
  Radio,
  X,
  FileCode,
  Tag,
  KeyRound,
  Shield,
  ArrowRight,
  Database,
} from 'lucide-react';
import {
  ThreatIntelIndicator,
  ThreatIntelProvider,
  IndicatorReputation,
  IndicatorType,
  Alert,
  Incident,
} from '../types';
import {
  fetchThreatIntelProviders,
  fetchThreatIntelIndicators,
  fetchThreatIntelIndicatorDetail,
  fetchThreatIntelRelatedAlerts,
  fetchThreatIntelRelatedIncidents,
  enrichIndicatorOnDemand,
} from '../services/api';
import { SeverityBadge } from '../components/SeverityBadge';
import { RiskScoreMeter } from '../components/RiskScoreMeter';

interface ThreatIntelligenceProps {
  onSelectAlert?: (alert: Alert) => void;
  onSelectIncident?: (incident: Incident) => void;
  initialIndicator?: string | null;
}

export const ThreatIntelligence: React.FC<ThreatIntelligenceProps> = ({
  onSelectAlert,
  onSelectIncident,
  initialIndicator,
}) => {
  const [providers, setProviders] = useState<ThreatIntelProvider[]>([]);
  const [indicators, setIndicators] = useState<ThreatIntelIndicator[]>([]);
  const [selectedIndicator, setSelectedIndicator] = useState<ThreatIntelIndicator | null>(null);
  const [relatedAlerts, setRelatedAlerts] = useState<Alert[]>([]);
  const [relatedIncidents, setRelatedIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [enriching, setEnriching] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Filters
  const [reputationFilter, setReputationFilter] = useState<string>('ALL');
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Manual Enrichment Input
  const [inputIndicator, setInputIndicator] = useState<string>('');
  const [inputType, setInputType] = useState<string>('auto');
  const [forceRefresh, setForceRefresh] = useState<boolean>(false);

  const loadData = useCallback(async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const [provs, inds] = await Promise.all([
        fetchThreatIntelProviders(),
        fetchThreatIntelIndicators({
          reputation: reputationFilter,
          indicator_type: typeFilter,
          search: searchQuery,
        }),
      ]);
      setProviders(provs);
      setIndicators(inds);

      if (initialIndicator && !selectedIndicator) {
        const found = inds.find(
          (i) => i.indicator.toLowerCase() === initialIndicator.toLowerCase()
        );
        if (found) {
          handleSelectIndicator(found);
        } else {
          // Trigger lookup
          try {
            const detail = await fetchThreatIntelIndicatorDetail(initialIndicator);
            handleSelectIndicator(detail);
          } catch {
            // ignore
          }
        }
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to load threat intelligence telemetry.');
    } finally {
      setLoading(false);
    }
  }, [reputationFilter, typeFilter, searchQuery, initialIndicator]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleSelectIndicator = async (indicator: ThreatIntelIndicator) => {
    setSelectedIndicator(indicator);
    try {
      const [alerts, incidents] = await Promise.all([
        fetchThreatIntelRelatedAlerts(indicator.indicator),
        fetchThreatIntelRelatedIncidents(indicator.indicator),
      ]);
      setRelatedAlerts(alerts);
      setRelatedIncidents(incidents);
    } catch (err) {
      console.error('Failed to load related alerts/incidents:', err);
    }
  };

  const handleManualEnrich = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputIndicator.trim()) return;

    setEnriching(true);
    setErrorMsg(null);
    setSuccessMsg(null);

    try {
      const result = await enrichIndicatorOnDemand({
        indicator: inputIndicator.trim(),
        indicator_type: inputType === 'auto' ? undefined : inputType,
        force_refresh: forceRefresh,
      });

      setSuccessMsg(`Indicator ${result.indicator} enriched: ${result.reputation.toUpperCase()}`);
      setInputIndicator('');
      await loadData();
      handleSelectIndicator(result);
    } catch (err: any) {
      setErrorMsg(err.message || 'Enrichment failed.');
    } finally {
      setEnriching(false);
    }
  };

  // Metrics summary
  const maliciousCount = indicators.filter((i) => i.reputation === 'malicious').length;
  const suspiciousCount = indicators.filter((i) => i.reputation === 'suspicious').length;
  const cleanCount = indicators.filter((i) => i.reputation === 'clean').length;
  const totalIndicators = indicators.length;

  const getReputationBadge = (rep: IndicatorReputation | string) => {
    switch (rep?.toLowerCase()) {
      case 'malicious':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold bg-rose-950/80 text-rose-400 border border-rose-800">
            <ShieldAlert className="h-3 w-3" />
            MALICIOUS
          </span>
        );
      case 'suspicious':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold bg-amber-950/80 text-amber-400 border border-amber-800">
            <AlertTriangle className="h-3 w-3" />
            SUSPICIOUS
          </span>
        );
      case 'clean':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-800">
            <ShieldCheck className="h-3 w-3" />
            CLEAN
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
            <Clock className="h-3 w-3" />
            UNKNOWN
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-cyan-950/60 border border-cyan-800/50 text-cyan-400">
              <Globe2 className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
                Threat Intelligence & Indicator Enrichment
                <span className="text-[10px] px-2 py-0.5 rounded font-mono font-semibold bg-cyan-950 text-cyan-400 border border-cyan-800/60">
                  PHASE 5 OPERATIONAL
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                Normalized multi-provider IOC enrichment, deterministic risk adjustment, and local Redis caching
              </p>
            </div>
          </div>
        </div>

        <button
          onClick={loadData}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 text-xs font-mono text-slate-300 transition"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
          <span>Refresh Feeds</span>
        </button>
      </div>

      {/* Notification Banners */}
      {errorMsg && (
        <div className="flex items-center justify-between p-3 rounded-lg bg-rose-950/40 border border-rose-800/60 text-xs text-rose-300 font-mono">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0" />
            <span>{errorMsg}</span>
          </div>
          <button onClick={() => setErrorMsg(null)} className="text-rose-400 hover:text-rose-200">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {successMsg && (
        <div className="flex items-center justify-between p-3 rounded-lg bg-emerald-950/40 border border-emerald-800/60 text-xs text-emerald-300 font-mono">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            <span>{successMsg}</span>
          </div>
          <button onClick={() => setSuccessMsg(null)} className="text-emerald-400 hover:text-emerald-200">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* KPI Overview Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 font-mono">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>TOTAL INDICATORS</span>
            <Layers className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-slate-100">{totalIndicators}</div>
          <div className="text-[10px] text-slate-500 mt-1">Cataloged IOC database records</div>
        </div>

        <div className="rounded-xl border border-rose-900/50 bg-rose-950/10 p-4 font-mono">
          <div className="flex items-center justify-between text-rose-400 text-xs mb-1">
            <span>MALICIOUS IOCs</span>
            <ShieldAlert className="h-4 w-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-400">{maliciousCount}</div>
          <div className="text-[10px] text-rose-500/80 mt-1">High-risk adversary entities</div>
        </div>

        <div className="rounded-xl border border-amber-900/50 bg-amber-950/10 p-4 font-mono">
          <div className="flex items-center justify-between text-amber-400 text-xs mb-1">
            <span>SUSPICIOUS IOCs</span>
            <AlertTriangle className="h-4 w-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400">{suspiciousCount}</div>
          <div className="text-[10px] text-amber-500/80 mt-1">Elevated risk probes & scanners</div>
        </div>

        <div className="rounded-xl border border-emerald-900/50 bg-emerald-950/10 p-4 font-mono">
          <div className="flex items-center justify-between text-emerald-400 text-xs mb-1">
            <span>CLEAN / VERIFIED</span>
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400">{cleanCount}</div>
          <div className="text-[10px] text-emerald-500/80 mt-1">RFC1918 & trusted infrastructure</div>
        </div>
      </div>

      {/* Provider Health & Status Cards */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3 font-mono">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Radio className="h-4 w-4 text-cyan-400" />
            <h2 className="text-xs font-bold text-slate-200 tracking-wider">
              INTELLIGENCE PROVIDER STATUS & API INTEGRATIONS
            </h2>
          </div>
          <span className="text-[10px] text-slate-500">
            Keys from environment only • Never returned to client
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {providers.map((p) => {
            const isConf = p.configured;
            return (
              <div
                key={p.name}
                className={`p-3 rounded-lg border text-xs ${
                  isConf
                    ? 'border-emerald-800/60 bg-emerald-950/20'
                    : 'border-slate-800 bg-slate-950/60'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-bold text-slate-200 uppercase">{p.name}</span>
                  {isConf ? (
                    <span className="inline-flex items-center gap-1 text-[10px] text-emerald-400 font-semibold">
                      <CheckCircle2 className="h-3 w-3" />
                      CONFIGURED
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-[10px] text-slate-500">
                      <Clock className="h-3 w-3" />
                      UNCONFIGURED
                    </span>
                  )}
                </div>
                <div className="space-y-1 text-[11px] text-slate-400">
                  <div className="flex justify-between">
                    <span>Availability:</span>
                    <span className={p.available ? 'text-emerald-400 font-semibold' : 'text-slate-500'}>
                      {p.available ? 'Active' : 'Offline / Standby'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Rate Limited:</span>
                    <span className={p.rate_limited ? 'text-amber-400' : 'text-slate-400'}>
                      {p.rate_limited ? 'Yes (60s backoff)' : 'No'}
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-500 truncate pt-1">
                    Types: {p.supported_types.join(', ')}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Manual / On-Demand Enrichment Form */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 font-mono space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Search className="h-4 w-4 text-cyan-400" />
            <h2 className="text-xs font-bold text-slate-200 tracking-wider">
              ON-DEMAND INDICATOR ENRICHMENT & SSRF-SAFE LOOKUP
            </h2>
          </div>
          <span className="text-[10px] text-slate-500">
            Strict input validation • SSRF protection enabled
          </span>
        </div>

        <form onSubmit={handleManualEnrich} className="grid grid-cols-1 md:grid-cols-12 gap-3 text-xs">
          <div className="md:col-span-6">
            <input
              type="text"
              placeholder="Enter IP (e.g. 198.51.100.23), domain, URL, or hash..."
              value={inputIndicator}
              onChange={(e) => setInputIndicator(e.target.value)}
              className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/60"
            />
          </div>

          <div className="md:col-span-3">
            <select
              value={inputType}
              onChange={(e) => setInputType(e.target.value)}
              className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500/60"
            >
              <option value="auto">Auto-Detect Type</option>
              <option value="ipv4">IPv4 Address</option>
              <option value="ipv6">IPv6 Address</option>
              <option value="domain">Domain Name</option>
              <option value="url">Web URL</option>
              <option value="hash">File Hash (MD5/SHA256)</option>
            </select>
          </div>

          <div className="md:col-span-3 flex items-center gap-2">
            <label className="flex items-center gap-1.5 text-[11px] text-slate-400 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={forceRefresh}
                onChange={(e) => setForceRefresh(e.target.checked)}
                className="rounded bg-slate-950 border-slate-800 text-cyan-500 focus:ring-0"
              />
              <span>Bypass Cache</span>
            </label>

            <button
              type="submit"
              disabled={enriching || !inputIndicator.trim()}
              className="flex-1 py-2 px-3 rounded bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-slate-950 font-bold text-xs transition flex items-center justify-center gap-1.5"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${enriching ? 'animate-spin' : ''}`} />
              <span>{enriching ? 'Querying...' : 'Enrich IOC'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Filter Toolbar & Search */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 font-mono text-xs space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search indicators or tags..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/50"
            />
          </div>

          <select
            value={reputationFilter}
            onChange={(e) => setReputationFilter(e.target.value)}
            className="px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500/50"
          >
            <option value="ALL">All Reputations</option>
            <option value="malicious">Malicious</option>
            <option value="suspicious">Suspicious</option>
            <option value="clean">Clean</option>
            <option value="unknown">Unknown</option>
          </select>

          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500/50"
          >
            <option value="ALL">All Indicator Types</option>
            <option value="ipv4">IPv4</option>
            <option value="ipv6">IPv6</option>
            <option value="domain">Domain</option>
            <option value="url">URL</option>
            <option value="hash">Hash</option>
          </select>
        </div>
      </div>

      {/* Main Grid: Indicators Catalog & Details Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Table of Indicators */}
        <div className={`space-y-4 ${selectedIndicator ? 'lg:col-span-7' : 'lg:col-span-12'}`}>
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-950 border-b border-slate-800 text-slate-400 text-[11px]">
                  <tr>
                    <th className="py-3 px-4">REPUTATION</th>
                    <th className="py-3 px-4">INDICATOR</th>
                    <th className="py-3 px-4">TYPE</th>
                    <th className="py-3 px-4">CONFIDENCE</th>
                    <th className="py-3 px-4">PROVIDER</th>
                    <th className="py-3 px-4">TAGS</th>
                    <th className="py-3 px-4">LAST SEEN</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {indicators.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-8 text-center text-slate-500">
                        No threat intelligence indicators found matching criteria.
                      </td>
                    </tr>
                  ) : (
                    indicators.map((ind) => {
                      const isSelected = selectedIndicator?.indicator === ind.indicator;
                      return (
                        <tr
                          key={`${ind.indicator}-${ind.indicator_type}`}
                          onClick={() => handleSelectIndicator(ind)}
                          className={`hover:bg-slate-800/50 cursor-pointer transition ${
                            isSelected ? 'bg-cyan-950/20 border-l-2 border-cyan-500' : ''
                          }`}
                        >
                          <td className="py-3 px-4">
                            {getReputationBadge(ind.reputation)}
                          </td>
                          <td className="py-3 px-4 font-semibold text-slate-200 max-w-[200px] truncate">
                            {ind.indicator}
                          </td>
                          <td className="py-3 px-4 text-slate-400 uppercase text-[11px]">
                            {ind.indicator_type}
                          </td>
                          <td className="py-3 px-4">
                            <div className="flex items-center gap-2">
                              <span className="font-bold text-slate-200">{ind.confidence}%</span>
                              <div className="w-12 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                                <div
                                  className={`h-full ${
                                    ind.confidence >= 80
                                      ? 'bg-rose-500'
                                      : ind.confidence >= 50
                                      ? 'bg-amber-500'
                                      : 'bg-emerald-500'
                                  }`}
                                  style={{ width: `${ind.confidence}%` }}
                                />
                              </div>
                            </div>
                          </td>
                          <td className="py-3 px-4 text-slate-400 text-[11px]">
                            {ind.provider}
                          </td>
                          <td className="py-3 px-4">
                            <div className="flex flex-wrap gap-1 max-w-[150px]">
                              {(ind.tags || []).slice(0, 2).map((t) => (
                                <span
                                  key={t}
                                  className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700/60"
                                >
                                  {t}
                                </span>
                              ))}
                              {(ind.tags || []).length > 2 && (
                                <span className="text-[10px] text-slate-500">
                                  +{ind.tags.length - 2}
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="py-3 px-4 text-slate-400 text-[11px] whitespace-nowrap">
                            {ind.last_seen ? new Date(ind.last_seen).toLocaleTimeString() : 'N/A'}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Indicator Details Inspector (5 cols) */}
        {selectedIndicator && (
          <div className="lg:col-span-5 space-y-4">
            <div className="rounded-xl border border-cyan-800/60 bg-slate-900/90 p-5 space-y-4 font-mono shadow-xl relative">
              {/* Close Button */}
              <button
                onClick={() => setSelectedIndicator(null)}
                className="absolute top-4 right-4 text-slate-400 hover:text-slate-200 transition"
              >
                <X className="h-4 w-4" />
              </button>

              <div>
                <span className="text-[10px] text-cyan-400 uppercase tracking-wider font-bold block mb-1">
                  INDICATOR INTELLIGENCE DOSSIER
                </span>
                <h3 className="text-base font-bold text-slate-100 break-all">
                  {selectedIndicator.indicator}
                </h3>
                <div className="flex items-center gap-2 mt-2">
                  {getReputationBadge(selectedIndicator.reputation)}
                  <SeverityBadge severity={selectedIndicator.severity} size="sm" />
                  <span className="text-[11px] text-slate-400 uppercase bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                    Type: {selectedIndicator.indicator_type}
                  </span>
                </div>
              </div>

              {/* Dossier Metrics Grid */}
              <div className="grid grid-cols-2 gap-3 bg-slate-950 p-3 rounded border border-slate-800 text-xs">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase">Confidence</span>
                  <div className="text-slate-200 mt-0.5 font-bold flex items-center gap-1.5">
                    <span className="text-base text-cyan-400">{selectedIndicator.confidence}%</span>
                  </div>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 uppercase">Primary Provider</span>
                  <div className="text-slate-200 mt-0.5 font-semibold uppercase">
                    {selectedIndicator.provider}
                  </div>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 uppercase">Related Alerts</span>
                  <div className="text-slate-200 mt-0.5 font-bold text-sm text-amber-400">
                    {relatedAlerts.length}
                  </div>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 uppercase">Related Incidents</span>
                  <div className="text-slate-200 mt-0.5 font-bold text-sm text-rose-400">
                    {relatedIncidents.length}
                  </div>
                </div>
              </div>

              {/* Reporting Providers Consensus */}
              {selectedIndicator.providers_reporting && (
                <div>
                  <span className="text-[11px] text-slate-500 uppercase font-bold block mb-1.5">
                    Providers Reporting:
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedIndicator.providers_reporting.map((prov) => (
                      <span
                        key={prov}
                        className="px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800 text-[11px] text-cyan-300 uppercase"
                      >
                        {prov}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Tags */}
              {selectedIndicator.tags && selectedIndicator.tags.length > 0 && (
                <div>
                  <span className="text-[11px] text-slate-500 uppercase font-bold block mb-1.5">
                    Intelligence Tags:
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedIndicator.tags.map((tag) => (
                      <span
                        key={tag}
                        className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-[11px] text-slate-300"
                      >
                        #{tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Associated Alerts */}
              <div>
                <span className="text-[11px] text-slate-500 uppercase font-bold block mb-1.5">
                  Associated Alerts ({relatedAlerts.length}):
                </span>
                {relatedAlerts.length === 0 ? (
                  <p className="text-[11px] text-slate-500 italic p-2 rounded bg-slate-950 border border-slate-800">
                    No active alerts mapped to this indicator.
                  </p>
                ) : (
                  <div className="space-y-1.5 max-h-36 overflow-y-auto">
                    {relatedAlerts.map((a) => (
                      <div
                        key={a.id}
                        onClick={() => onSelectAlert && onSelectAlert(a)}
                        className="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800 hover:border-cyan-500/50 cursor-pointer text-xs transition"
                      >
                        <div className="truncate pr-2">
                          <span className="text-slate-300 font-semibold">{a.title}</span>
                          <span className="block text-[10px] text-slate-500">
                            Risk: {a.risk_score} • {a.status}
                          </span>
                        </div>
                        <SeverityBadge severity={a.severity} size="sm" />
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Associated Incidents */}
              <div>
                <span className="text-[11px] text-slate-500 uppercase font-bold block mb-1.5">
                  Associated Incidents ({relatedIncidents.length}):
                </span>
                {relatedIncidents.length === 0 ? (
                  <p className="text-[11px] text-slate-500 italic p-2 rounded bg-slate-950 border border-slate-800">
                    No active incidents mapped to this indicator.
                  </p>
                ) : (
                  <div className="space-y-1.5 max-h-32 overflow-y-auto">
                    {relatedIncidents.map((inc) => (
                      <div
                        key={inc.id}
                        onClick={() => onSelectIncident && onSelectIncident(inc)}
                        className="flex items-center justify-between p-2 rounded bg-slate-950 border border-rose-900/40 hover:border-rose-500 cursor-pointer text-xs transition"
                      >
                        <div className="truncate pr-2">
                          <span className="text-rose-300 font-semibold">{inc.title}</span>
                          <span className="block text-[10px] text-slate-500">
                            {inc.status} • Risk: {inc.risk_score}
                          </span>
                        </div>
                        <SeverityBadge severity={inc.severity} size="sm" />
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Raw Provider Metadata (Safe, No Secrets) */}
              {selectedIndicator.raw_response && (
                <div>
                  <span className="text-[11px] text-slate-500 uppercase font-bold block mb-1">
                    Safe Normalized Metadata:
                  </span>
                  <pre className="p-2 rounded bg-slate-950 border border-slate-800 text-[10px] text-cyan-400 overflow-x-auto max-h-28">
                    {JSON.stringify(selectedIndicator.raw_response, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
