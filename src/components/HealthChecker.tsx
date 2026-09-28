import React, { useState } from 'react';
import { Play, Copy, Check, Terminal, Shield, AlertCircle, ArrowUpRight } from 'lucide-react';
import { HealthCheckResponse } from '../types';

interface HealthCheckerProps {
  healthData: HealthCheckResponse | null;
  onTriggerCheck: () => Promise<void>;
  isLoading: boolean;
}

export const HealthChecker: React.FC<HealthCheckerProps> = ({
  healthData,
  onTriggerCheck,
  isLoading,
}) => {
  const [copied, setCopied] = useState(false);
  const [selectedEndpoint, setSelectedEndpoint] = useState('/health');

  const handleCopy = () => {
    if (!healthData) return;
    navigator.clipboard.writeText(JSON.stringify(healthData, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-5 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <Terminal className="h-4 w-4" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-slate-100 font-mono">
              Live Health-Check Diagnostic Console
            </h3>
            <p className="text-xs text-slate-400">
              Evaluates FastAPI dispatcher, PostgreSQL 16 connectivity, and Redis message broker.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <select
            value={selectedEndpoint}
            onChange={(e) => setSelectedEndpoint(e.target.value)}
            className="rounded border border-slate-700 bg-slate-800 px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-emerald-500"
          >
            <option value="/health">GET /health (Root)</option>
            <option value="/api/v1/health">GET /api/v1/health (Versioned)</option>
          </select>

          <button
            onClick={() => onTriggerCheck()}
            disabled={isLoading}
            className="flex items-center gap-1.5 rounded bg-emerald-500 hover:bg-emerald-600 active:scale-95 text-slate-950 font-bold px-3 py-1.5 text-xs font-mono transition cursor-pointer disabled:opacity-50"
          >
            <Play className={`h-3 w-3 ${isLoading ? 'animate-spin' : ''}`} />
            <span>{isLoading ? 'EXECUTING...' : 'RUN CHECK'}</span>
          </button>
        </div>
      </div>

      {/* Terminal View */}
      <div className="relative rounded-lg border border-slate-800 bg-slate-950 overflow-hidden font-mono text-xs">
        <div className="flex items-center justify-between border-b border-slate-800/80 bg-slate-900/80 px-4 py-2">
          <div className="flex items-center gap-2 text-slate-400 text-[11px]">
            <span className="h-2 w-2 rounded-full bg-emerald-400 inline-block" />
            <span>HTTP/1.1 200 OK • Content-Type: application/json</span>
          </div>
          <button
            onClick={handleCopy}
            className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200 transition cursor-pointer"
          >
            {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
            <span>{copied ? 'Copied' : 'Copy JSON'}</span>
          </button>
        </div>

        <pre className="p-4 text-emerald-300/90 overflow-x-auto text-[11px] leading-relaxed max-h-72">
          {healthData ? JSON.stringify(healthData, null, 2) : '// No check executed yet.'}
        </pre>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-slate-400 pt-1 font-mono">
        <div className="flex items-center gap-2">
          <span className="text-slate-500">API Documentation:</span>
          <span className="text-emerald-400">/docs</span>
          <span className="text-slate-600">•</span>
          <span className="text-cyan-400">/redoc</span>
        </div>
        <div className="flex items-center gap-1.5 text-slate-500">
          <span>Security Headers:</span>
          <span className="text-slate-300">nosniff, DENY, CSP strict</span>
        </div>
      </div>
    </div>
  );
};
