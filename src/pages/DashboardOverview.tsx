import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Radio,
  FolderKanban,
  Server,
  FileCode2,
  Activity,
  Layers,
  Terminal,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import { HealthCheckResponse } from '../types';
import { ServiceTopology } from '../components/ServiceTopology';
import { ArchitecturePipeline } from '../components/ArchitecturePipeline';
import { HealthChecker } from '../components/HealthChecker';
import { PhaseRoadmap } from '../components/PhaseRoadmap';

interface DashboardOverviewProps {
  healthData: HealthCheckResponse | null;
  onRefreshHealth: () => Promise<void>;
  isLoading: boolean;
}

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  healthData,
  onRefreshHealth,
  isLoading,
}) => {
  const quickStats = [
    {
      label: 'Core Services',
      value: '3 / 3',
      sub: 'FastAPI, PG16, Redis',
      status: 'healthy',
      icon: Server,
    },
    {
      label: 'Detection Rules Catalog',
      value: '10 Mapped',
      sub: 'Rules 001-010 (Phase 4)',
      status: 'active',
      icon: FileCode2,
    },
    {
      label: 'MITRE Coverage',
      value: '4 Tactics',
      sub: 'T1110, T1078, T1046, T1059',
      status: 'active',
      icon: ShieldAlert,
    },
    {
      label: 'Unit Test Coverage',
      value: '15 / 15 Pass',
      sub: 'Zero failures, 0 syntax err',
      status: 'healthy',
      icon: CheckCircle2,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Welcome Banner */}
      <div className="rounded-xl border border-slate-800 bg-gradient-to-r from-slate-900/90 via-slate-900/60 to-slate-950 p-5 shadow-lg">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-xs font-mono uppercase tracking-wider text-emerald-400 font-semibold">
                Defense Laboratory Node Ready
              </span>
            </div>
            <h2 className="text-xl font-bold text-slate-100 tracking-tight">
              SentinelX Defense Operations Center
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
              Enterprise SOC/SIEM threat monitoring platform with multi-event correlation,
              explainable risk scoring (0–100), and MITRE ATT&CK telemetry normalization.
            </p>
          </div>

          <div className="flex items-center gap-2.5">
            <div className="rounded-lg border border-slate-800 bg-slate-950/80 px-3.5 py-2 text-right">
              <div className="text-[10px] font-mono text-slate-500 uppercase">Current Phase</div>
              <div className="text-xs font-mono font-bold text-emerald-400">PHASE 1 : SKELETON</div>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/80 px-3.5 py-2 text-right">
              <div className="text-[10px] font-mono text-slate-500 uppercase">Version</div>
              <div className="text-xs font-mono font-bold text-slate-200">v0.1.0-alpha</div>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Status Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        {quickStats.map((stat, i) => {
          const Icon = stat.icon;
          return (
            <div
              key={i}
              className="rounded-lg border border-slate-800 bg-slate-900/50 p-4 hover:border-slate-700 transition"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono text-slate-400">{stat.label}</span>
                <div className="p-1.5 rounded bg-slate-800 text-emerald-400 border border-slate-700/60">
                  <Icon className="h-3.5 w-3.5" />
                </div>
              </div>
              <div className="text-lg font-bold font-mono text-slate-100">{stat.value}</div>
              <div className="text-[11px] font-mono text-slate-500 mt-0.5">{stat.sub}</div>
            </div>
          );
        })}
      </div>

      {/* Interactive Health Checker */}
      <HealthChecker
        healthData={healthData}
        onTriggerCheck={onRefreshHealth}
        isLoading={isLoading}
      />

      {/* Service Topology Grid */}
      <ServiceTopology services={healthData?.services || {}} />

      {/* Architecture Pipeline Flow */}
      <ArchitecturePipeline />

      {/* Phased Roadmap */}
      <PhaseRoadmap />
    </div>
  );
};
