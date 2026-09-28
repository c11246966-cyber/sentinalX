import React from 'react';
import { ServiceStatus } from '../types';

interface StatusBadgeProps {
  status: ServiceStatus | 'active' | 'in_development' | 'planned';
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, size = 'md' }) => {
  const getStyles = () => {
    switch (status) {
      case 'healthy':
      case 'active':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'degraded':
      case 'in_development':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'unhealthy':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'offline':
      case 'planned':
        return 'bg-slate-800 text-slate-400 border-slate-700';
      default:
        return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
    }
  };

  const getDotColor = () => {
    switch (status) {
      case 'healthy':
      case 'active':
        return 'bg-emerald-400 animate-pulse';
      case 'degraded':
      case 'in_development':
        return 'bg-amber-400';
      case 'unhealthy':
        return 'bg-rose-400 animate-ping';
      default:
        return 'bg-slate-500';
    }
  };

  const pad = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs font-mono';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border font-medium uppercase tracking-wider ${getStyles()} ${pad}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${getDotColor()}`} />
      {status.replace('_', ' ')}
    </span>
  );
};
