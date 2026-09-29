import React from 'react';
import { AlertSeverity } from '../types';

interface SeverityBadgeProps {
  severity: AlertSeverity | string;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'sm' }) => {
  const sev = (severity || 'INFORMATIONAL').toUpperCase();

  let styles = 'bg-slate-800 text-slate-300 border-slate-700';

  if (sev === 'CRITICAL') {
    styles = 'bg-rose-950/80 text-rose-300 border-rose-800/80 ring-1 ring-rose-500/20';
  } else if (sev === 'HIGH') {
    styles = 'bg-orange-950/80 text-orange-300 border-orange-800/80';
  } else if (sev === 'MEDIUM') {
    styles = 'bg-amber-950/80 text-amber-300 border-amber-800/80';
  } else if (sev === 'LOW') {
    styles = 'bg-blue-950/80 text-blue-300 border-blue-800/80';
  } else if (sev === 'INFORMATIONAL') {
    styles = 'bg-slate-900 text-slate-400 border-slate-800';
  }

  const sizeClass = size === 'sm' ? 'px-2 py-0.5 text-[10px]' : 'px-2.5 py-1 text-xs';

  return (
    <span className={`inline-flex items-center font-mono font-bold uppercase rounded border ${styles} ${sizeClass}`}>
      {sev}
    </span>
  );
};
