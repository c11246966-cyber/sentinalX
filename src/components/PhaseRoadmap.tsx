import React from 'react';
import { CheckCircle2, Clock, ShieldAlert, ArrowRight } from 'lucide-react';

export const PhaseRoadmap: React.FC = () => {
  const phases = [
    {
      phase: 1,
      name: 'Foundation & Scaffolding',
      status: 'completed',
      deliverables: [
        'Modular repository structure with clean separation of concerns',
        'FastAPI backend with CORS, security headers & lifespan manager',
        'React TypeScript frontend with dark SOC design language',
        'PostgreSQL 16 & Redis 7 Docker Compose orchestration',
        'Comprehensive healthcheck (/health & /api/v1/health)',
        'Automated unit tests (15/15 passing)',
      ],
    },
    {
      phase: 2,
      name: 'Database Models, Alembic & RBAC',
      status: 'upcoming',
      deliverables: [
        'Alembic migrations setup and execution',
        'Argon2 password hashing & JWT token issuance',
        'RBAC enforcement (Admin, Analyst, Viewer)',
        'Immutable audit logging subsystem',
      ],
    },
    {
      phase: 3,
      name: 'Event Ingestion & Normalization',
      status: 'upcoming',
      deliverables: [
        'POST /api/events with strict schema validation',
        'Preservation of raw JSON alongside indexed fields',
        'High-throughput asynchronous ingest queue',
      ],
    },
    {
      phase: 4,
      name: 'Detection Engine & 10 Initial Rules',
      status: 'upcoming',
      deliverables: [
        'Rules 001-010 (Brute force, port scan, abnormal burst, etc.)',
        'Sliding window stateful evaluation',
        'Alert generation & lifecycle tracking',
      ],
    },
    {
      phase: 5,
      name: 'Correlation & Explainable Risk (0–100)',
      status: 'upcoming',
      deliverables: [
        'Multi-event correlation across IP, host, and user',
        'Transparent factor-point risk calculation system',
        'MITRE ATT&CK technique mapping',
      ],
    },
    {
      phase: 6,
      name: 'Interactive SOC Dashboard UI',
      status: 'upcoming',
      deliverables: [
        'Alert triage board & investigation detail views',
        'Interactive telemetry filters & incident management',
        'Endpoint host inventory tracking',
      ],
    },
  ];

  return (
    <div className="space-y-3">
      <div>
        <h2 className="text-sm font-semibold text-slate-200 tracking-wide uppercase font-mono">
          SentinelX Architecture Roadmap & Phase Deliverables
        </h2>
        <p className="text-xs text-slate-400">
          Structured phased deployment following cybersecurity engineering standards.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {phases.map((item) => (
          <div
            key={item.phase}
            className={`rounded-lg border p-4 flex flex-col justify-between ${
              item.status === 'completed'
                ? 'border-emerald-500/30 bg-emerald-950/10'
                : 'border-slate-800 bg-slate-900/40'
            }`}
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono font-bold text-slate-200">
                  PHASE {item.phase}
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase ${
                    item.status === 'completed'
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      : 'bg-slate-800 text-slate-400 border border-slate-700'
                  }`}
                >
                  {item.status}
                </span>
              </div>

              <h4 className="text-xs font-semibold text-slate-100 mb-2.5">
                {item.name}
              </h4>

              <ul className="space-y-1.5 text-[11px] text-slate-400">
                {item.deliverables.map((deliv, idx) => (
                  <li key={idx} className="flex items-start gap-1.5">
                    <CheckCircle2
                      className={`h-3.5 w-3.5 shrink-0 mt-0.5 ${
                        item.status === 'completed' ? 'text-emerald-400' : 'text-slate-600'
                      }`}
                    />
                    <span>{deliv}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
