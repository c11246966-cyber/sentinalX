import React from 'react';

interface RiskScoreMeterProps {
  score: number;
  showBar?: boolean;
}

export const RiskScoreMeter: React.FC<RiskScoreMeterProps> = ({ score, showBar = false }) => {
  const clamped = Math.max(0, Math.min(100, score || 0));

  let colorClass = 'text-emerald-400 border-emerald-800 bg-emerald-950/60';
  let barColor = 'bg-emerald-500';

  if (clamped >= 85) {
    colorClass = 'text-rose-400 border-rose-800 bg-rose-950/60';
    barColor = 'bg-rose-500';
  } else if (clamped >= 70) {
    colorClass = 'text-orange-400 border-orange-800 bg-orange-950/60';
    barColor = 'bg-orange-500';
  } else if (clamped >= 45) {
    colorClass = 'text-amber-400 border-amber-800 bg-amber-950/60';
    barColor = 'bg-amber-500';
  } else if (clamped >= 20) {
    colorClass = 'text-blue-400 border-blue-800 bg-blue-950/60';
    barColor = 'bg-blue-500';
  }

  return (
    <div className="inline-flex flex-col gap-1">
      <span className={`inline-flex items-center justify-center font-mono font-bold text-xs px-2 py-0.5 rounded border ${colorClass}`}>
        {clamped}/100
      </span>
      {showBar && (
        <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
          <div className={`h-full ${barColor}`} style={{ width: `${clamped}%` }} />
        </div>
      )}
    </div>
  );
};
