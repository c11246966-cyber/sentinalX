import React from 'react';
import { Shield, Radio, Terminal, Cpu, Clock, RefreshCw } from 'lucide-react';
import { StatusBadge } from './StatusBadge';
import { RealtimeIndicator } from './RealtimeIndicator';
import { useRealtime } from '../services/realtime';

interface HeaderProps {
  onRefresh: () => void;
  isRefreshing: boolean;
  overallStatus: 'healthy' | 'degraded' | 'unhealthy';
  lastChecked: string;
}

export const Header: React.FC<HeaderProps> = ({
  onRefresh,
  isRefreshing,
  overallStatus,
  lastChecked,
}) => {
  const { status: realtimeStatus, reconnect } = useRealtime();

  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur-md sticky top-0 z-30 px-6 py-3.5">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        {/* Brand identity */}
        <div className="flex items-center gap-3">
          <div className="relative flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-emerald-500/20 to-cyan-500/10 border border-emerald-500/40 text-emerald-400 shadow-lg shadow-emerald-500/10">
            <Shield className="h-5 w-5" />
            <div className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full bg-emerald-500 ring-2 ring-slate-950" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold tracking-wider text-slate-100 uppercase font-mono">
                Sentinel<span className="text-emerald-400">X</span>
              </h1>
              <span className="rounded bg-emerald-950/80 px-2 py-0.5 text-[10px] font-mono font-semibold text-emerald-300 border border-emerald-800/60">
                PHASE 4 : SOC DASHBOARD & REALTIME
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono">
              ENTERPRISE DEFENSIVE CYBERSECURITY PLATFORM
            </p>
          </div>
        </div>

        {/* Real-time telemetry & connection indicators */}
        <div className="flex flex-wrap items-center gap-3 sm:gap-4">
          <RealtimeIndicator status={realtimeStatus} onReconnect={reconnect} />

          <div className="hidden sm:flex items-center gap-2 bg-slate-900/90 px-3 py-1.5 rounded-md border border-slate-800 text-xs font-mono">
            <Radio className="h-3.5 w-3.5 text-emerald-400 animate-pulse" />
            <span className="text-slate-400">HEALTH:</span>
            <StatusBadge status={overallStatus} size="sm" />
          </div>

          <div className="hidden md:flex items-center gap-2 bg-slate-900/90 px-3 py-1.5 rounded-md border border-slate-800 text-xs font-mono">
            <Cpu className="h-3.5 w-3.5 text-cyan-400" />
            <span className="text-slate-400">STACK:</span>
            <span className="text-slate-200">FastAPI • PG16 • SSE</span>
          </div>

          <div className="flex items-center gap-2 bg-slate-900/90 px-3 py-1.5 rounded-md border border-slate-800 text-xs font-mono">
            <Clock className="h-3.5 w-3.5 text-slate-400" />
            <span className="text-slate-400">PING:</span>
            <span className="text-slate-300">{lastChecked ? new Date(lastChecked).toLocaleTimeString() : 'N/A'}</span>
          </div>

          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            className="flex items-center gap-1.5 rounded-md bg-emerald-500/10 hover:bg-emerald-500/20 active:scale-95 text-emerald-400 border border-emerald-500/30 px-3 py-1.5 text-xs font-mono font-medium transition cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
            <span>{isRefreshing ? 'POLLING...' : 'HEALTH PING'}</span>
          </button>
        </div>
      </div>
    </header>
  );
};
