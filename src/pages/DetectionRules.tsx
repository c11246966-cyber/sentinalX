import React, { useState, useEffect } from 'react';
import {
  FileCode2,
  ExternalLink,
  Shield,
  Layers,
  Crosshair,
  CheckCircle2,
  Search,
} from 'lucide-react';
import { DetectionRule, MitreTechnique } from '../types';
import { fetchRules, fetchMitreCatalog } from '../services/api';
import { SeverityBadge } from '../components/SeverityBadge';

export const DetectionRules: React.FC = () => {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [mitreCatalog, setMitreCatalog] = useState<MitreTechnique[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterCategory, setFilterCategory] = useState('ALL');
  const [search, setSearch] = useState('');

  useEffect(() => {
    async function loadData() {
      try {
        const [rData, mData] = await Promise.all([fetchRules(), fetchMitreCatalog()]);
        setRules(rData);
        setMitreCatalog(mData);
      } catch (err) {
        console.error('Failed to load rules & MITRE catalog:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const filteredRules = rules.filter((r) => {
    if (filterCategory !== 'ALL' && r.category !== filterCategory) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        r.name.toLowerCase().includes(q) ||
        r.category.toLowerCase().includes(q) ||
        (r.mitre_technique && r.mitre_technique.toLowerCase().includes(q))
      );
    }
    return true;
  });

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <FileCode2 className="h-5 w-5 text-indigo-400" />
            <h2 className="text-lg font-bold text-slate-100 uppercase tracking-wide">
              Detection Rules & MITRE ATT&CK Catalog
            </h2>
            <span className="rounded bg-indigo-950/80 border border-indigo-800 px-2 py-0.5 text-xs text-indigo-300">
              {rules.length} Rules Active
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Deterministic, explainable rule catalog mapped directly to ATT&CK tactics (zero black-box AI)
          </p>
        </div>
      </div>

      {/* Filter toolbar */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search rule name, category..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 placeholder:text-slate-600 focus:outline-none"
            />
          </div>

          <select
            value={filterCategory}
            onChange={(e) => setFilterCategory(e.target.value)}
            className="px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none"
          >
            <option value="ALL">All Categories</option>
            <option value="network">Network</option>
            <option value="authentication">Authentication</option>
            <option value="web">Web Application</option>
            <option value="process">Host & Process</option>
          </select>
        </div>
      </div>

      {/* Rules Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <span className="font-bold text-slate-300 uppercase tracking-wider">Engine Detection Analyzers</span>
          <span className="text-[11px] text-emerald-400 flex items-center gap-1">
            <CheckCircle2 className="h-3.5 w-3.5" />
            <span>All 9 Rules Compiled & Enabled</span>
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="bg-slate-950 border-b border-slate-800 text-slate-400 text-[11px]">
              <tr>
                <th className="py-3 px-4">SEVERITY</th>
                <th className="py-3 px-4">RULE NAME</th>
                <th className="py-3 px-4">CATEGORY</th>
                <th className="py-3 px-4">DETECTION TYPE</th>
                <th className="py-3 px-4">MITRE TECHNIQUE</th>
                <th className="py-3 px-4">STATUS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredRules.map((r) => (
                <tr key={r.id} className="hover:bg-slate-800/50 transition">
                  <td className="py-3 px-4">
                    <SeverityBadge severity={r.severity} size="sm" />
                  </td>
                  <td className="py-3 px-4 font-bold text-slate-200">{r.name}</td>
                  <td className="py-3 px-4 text-slate-300 uppercase text-[10px]">{r.category}</td>
                  <td className="py-3 px-4 text-slate-400 font-mono">{r.rule_type}</td>
                  <td className="py-3 px-4">
                    {r.mitre_technique ? (
                      <a
                        href={`https://attack.mitre.org/techniques/${r.mitre_technique.replace('.', '/')}/`}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 text-cyan-400 hover:underline font-bold"
                      >
                        <span>{r.mitre_technique}</span>
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    ) : (
                      <span className="text-slate-600">—</span>
                    )}
                  </td>
                  <td className="py-3 px-4">
                    <span className="inline-flex items-center gap-1 text-emerald-400 text-[10px] uppercase font-bold">
                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                      Active
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* MITRE ATT&CK Catalog */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
        <div className="flex items-center gap-2">
          <Crosshair className="h-4 w-4 text-cyan-400" />
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
            MITRE ATT&CK Enterprise Matrix Coverage
          </h3>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {mitreCatalog.map((m) => (
            <div key={m.id} className="p-3 rounded border border-slate-800 bg-slate-950 space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-bold text-cyan-400">{m.id}</span>
                <span className="text-[10px] uppercase tracking-wider text-slate-500">{m.tactic}</span>
              </div>
              <div className="text-slate-200 font-semibold truncate" title={m.technique}>
                {m.technique}
              </div>
              <a
                href={m.url}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 text-[10px] text-slate-400 hover:text-cyan-300 pt-1"
              >
                <span>View ATT&CK Spec</span>
                <ExternalLink className="h-2.5 w-2.5" />
              </a>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
