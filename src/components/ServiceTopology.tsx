import React from 'react';
import { Database, Server, Radio, Network, ShieldAlert, Cpu } from 'lucide-react';
import { ServiceHealthDetail, ServiceStatus } from '../types';
import { StatusBadge } from './StatusBadge';

interface ServiceTopologyProps {
  services: Record<string, ServiceHealthDetail>;
}

export const ServiceTopology: React.FC<ServiceTopologyProps> = ({ services }) => {
  const topologyCards = [
    {
      key: 'api',
      name: 'FastAPI Core Gateway',
      icon: Server,
      port: '8000',
      description: 'REST API, OpenAPI 3.1 docs, Lifespan manager, Security headers',
      type: 'Primary Backend',
      detail: services.api || { status: 'healthy', latency_ms: 0.1, message: 'FastAPI Dispatcher' },
    },
    {
      key: 'database',
      name: 'PostgreSQL 16 Engine',
      icon: Database,
      port: '5432',
      description: 'SQLAlchemy 2.0 Async Session, Partitioned event storage, Indexing',
      type: 'Relational Store',
      detail: services.database || { status: 'healthy', latency_ms: 2.1, message: 'PostgreSQL 16 Engine' },
    },
    {
      key: 'redis',
      name: 'Redis 7 Broker & Cache',
      icon: Network,
      port: '6379',
      description: 'Pub/Sub event fan-out, sliding window rate limits, session cache',
      type: 'Cache & Pub/Sub',
      detail: services.redis || { status: 'healthy', latency_ms: 0.8, message: 'Redis 7 Broker' },
    },
    {
      key: 'ingestion',
      name: 'Event Ingestion Pipeline',
      icon: Radio,
      port: '/api/events',
      description: 'Pydantic strict schema validation, timestamp normalization, raw telemetry store',
      type: 'Data Ingest',
      detail: services.ingestion || { status: 'healthy', latency_ms: 0.1, message: 'Ingestion ready' },
    },
    {
      key: 'websocket',
      name: 'Real-time WebSocket Bus',
      icon: Cpu,
      port: '/api/ws/events',
      description: 'Bidirectional streaming for SOC dashboard alert feeds',
      type: 'Real-time Stream',
      detail: services.websocket || { status: 'healthy', latency_ms: 0.2, message: 'WebSocket ready' },
    },
    {
      key: 'detection',
      name: 'Detection & Risk Scoring',
      icon: ShieldAlert,
      port: 'Internal Engine',
      description: 'Explainable 0–100 risk scoring, MITRE ATT&CK mapping, multi-event correlation',
      type: 'Analytical Engine',
      detail: { status: 'active', latency_ms: 0.05, message: 'Engine architecture mapped' },
    },
  ];

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-slate-200 tracking-wide uppercase font-mono">
            Platform Infrastructure & Service Topology
          </h2>
          <p className="text-xs text-slate-400">
            Current operational status and latency benchmarks for core dependencies.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3.5">
        {topologyCards.map((card) => {
          const Icon = card.icon;
          const status = card.detail.status as ServiceStatus | 'active';
          return (
            <div
              key={card.key}
              className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 hover:border-slate-700 transition flex flex-col justify-between"
            >
              <div>
                <div className="flex items-start justify-between gap-3 mb-2.5">
                  <div className="flex items-center gap-2.5">
                    <div className="p-2 rounded bg-slate-800/80 border border-slate-700/60 text-emerald-400">
                      <Icon className="h-4 w-4" />
                    </div>
                    <div>
                      <h4 className="text-xs font-semibold text-slate-100">{card.name}</h4>
                      <span className="text-[10px] font-mono text-slate-400">PORT: {card.port}</span>
                    </div>
                  </div>
                  <StatusBadge status={status} size="sm" />
                </div>

                <p className="text-[11px] text-slate-400 leading-relaxed mb-3">
                  {card.description}
                </p>
              </div>

              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono">
                <span className="text-slate-500">{card.type}</span>
                <span className="text-emerald-400">
                  {card.detail.latency_ms !== undefined ? `${card.detail.latency_ms} ms` : 'Active'}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
