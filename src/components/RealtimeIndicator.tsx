import React from 'react';
import { Wifi, WifiOff, RefreshCw } from 'lucide-react';
import { RealtimeStatus } from '../types';

interface RealtimeIndicatorProps {
  status: RealtimeStatus;
  onReconnect?: () => void;
}

export const RealtimeIndicator: React.FC<RealtimeIndicatorProps> = ({ status, onReconnect }) => {
  if (status === 'connected') {
    return (
      <div
        title="Real-time WebSocket connected and receiving telemetry stream (LIVE)"
        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-emerald-950/80 border border-emerald-800/80 text-[11px] font-mono text-emerald-300"
      >
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
          <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
        </span>
        <Wifi className="h-3 w-3 text-emerald-400" />
        <span className="font-bold tracking-wider">LIVE</span>
      </div>
    );
  }

  if (status === 'reconnecting') {
    return (
      <button
        onClick={onReconnect}
        title="Attempting to re-establish real-time WebSocket connection..."
        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-amber-950/80 border border-amber-800/80 text-[11px] font-mono text-amber-300 hover:bg-amber-900/60 transition cursor-pointer"
      >
        <RefreshCw className="h-3 w-3 animate-spin text-amber-400" />
        <span className="font-bold tracking-wider">RECONNECTING</span>
      </button>
    );
  }

  return (
    <button
      onClick={onReconnect}
      title="WebSocket offline. Click to reconnect."
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-rose-950/80 border border-rose-800/80 text-[11px] font-mono text-rose-300 hover:bg-rose-900/60 transition cursor-pointer"
    >
      <WifiOff className="h-3 w-3 text-rose-400" />
      <span className="font-bold tracking-wider">OFFLINE</span>
    </button>
  );
};
