import React from 'react';
import {
  ArrowRight,
  Database,
  Shield,
  Layers,
  Activity,
  Search,
  AlertTriangle,
  FolderLock,
  MonitorDot,
  Radio,
} from 'lucide-react';
import { PipelineStage } from '../types';

export const ArchitecturePipeline: React.FC = () => {
  const stages: PipelineStage[] = [
    {
      id: 'collectors',
      step: 1,
      title: 'Collectors',
      category: 'Telemetry Ingest',
      description: 'Windows Security Event Log & Linux Syslog/Auditd agents capturing telemetry.',
      phase: 9,
      status: 'planned',
    },
    {
      id: 'ingestion',
      step: 2,
      title: 'Ingestion API',
      category: 'Validation Gateway',
      description: 'FastAPI POST /api/events with Pydantic validation & rate limiting.',
      phase: 3,
      status: 'in_development',
    },
    {
      id: 'normalizer',
      step: 3,
      title: 'Normalizer & Storage',
      category: 'Event Persistence',
      description: 'PostgreSQL 16 storage preserving normalized fields and raw event JSON.',
      phase: 3,
      status: 'in_development',
    },
    {
      id: 'detection',
      step: 4,
      title: 'Detection Engine',
      category: 'Rule Processing',
      description: 'Modular rule engine evaluating sliding time-window thresholds (Rule 001-010).',
      phase: 4,
      status: 'planned',
      mitreRef: 'T1110, T1078, T1046',
    },
    {
      id: 'correlation',
      step: 5,
      title: 'Correlation Engine',
      category: 'Multi-Event Graph',
      description: 'Aggregates multi-stage attacks across IP, host, username, and time-windows.',
      phase: 5,
      status: 'planned',
    },
    {
      id: 'risk',
      step: 6,
      title: 'Explainable Risk',
      category: '0–100 Scoring',
      description: 'Calculates explainable risk scores with explicit factor contribution breakdown.',
      phase: 5,
      status: 'planned',
    },
    {
      id: 'intel',
      step: 7,
      title: 'Threat Intel',
      category: 'Indicator Enrichment',
      description: 'Enriches indicators with VirusTotal, AbuseIPDB, and AlienVault OTX.',
      phase: 8,
      status: 'planned',
    },
    {
      id: 'alerts',
      step: 8,
      title: 'Alert Lifecycle',
      category: 'State Machine',
      description: 'Tracks alert triage: NEW -> INVESTIGATING -> RESOLVED / FALSE_POSITIVE.',
      phase: 4,
      status: 'planned',
    },
    {
      id: 'incidents',
      step: 9,
      title: 'Incidents & Response',
      category: 'Analyst Dispatch',
      description: 'Incident management with analyst assignment and safe lab response actions.',
      phase: 5,
      status: 'planned',
    },
    {
      id: 'soc',
      step: 10,
      title: 'SOC Dashboard',
      category: 'Analyst Cockpit',
      description: 'Dark SOC UI receiving real-time updates via WebSockets.',
      phase: 6,
      status: 'active',
    },
  ];

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-sm font-semibold text-slate-200 tracking-wide uppercase font-mono">
          Defensive Detection & Ingestion Architecture Pipeline
        </h2>
        <p className="text-xs text-slate-400">
          Logical flow from endpoint telemetry ingestion through detection, correlation, and SOC triage.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3">
        {stages.map((stage) => (
          <div
            key={stage.id}
            className="rounded-lg border border-slate-800 bg-slate-900/40 p-3 hover:border-slate-700 transition flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="flex h-5 w-5 items-center justify-center rounded-full bg-emerald-500/10 text-emerald-400 text-[10px] font-mono font-bold border border-emerald-500/30">
                  {stage.step}
                </span>
                <span className="text-[9px] font-mono text-slate-400 px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700">
                  PHASE {stage.phase}
                </span>
              </div>
              <h4 className="text-xs font-semibold text-slate-100 mb-0.5">{stage.title}</h4>
              <p className="text-[10px] font-mono text-emerald-400/90 mb-1.5">{stage.category}</p>
              <p className="text-[11px] text-slate-400 leading-snug">{stage.description}</p>
            </div>

            {stage.mitreRef && (
              <div className="mt-2.5 pt-2 border-t border-slate-800/80 text-[10px] font-mono text-cyan-400">
                MITRE: {stage.mitreRef}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};
