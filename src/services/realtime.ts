import { useEffect, useState, useRef, useCallback } from 'react';
import { RealtimeStatus } from '../types';

export type RealtimeCallback = (message: {
  type: string;
  timestamp: string;
  data: any;
  alert?: any;
  incident?: any;
  event?: any;
  host?: any;
}) => void;

class RealtimeClient {
  private ws: WebSocket | null = null;
  private sse: EventSource | null = null;
  private listeners: Set<RealtimeCallback> = new Set();
  private statusListeners: Set<(status: RealtimeStatus) => void> = new Set();
  private status: RealtimeStatus = 'disconnected';
  private reconnectTimeout: any = null;
  private pingInterval: any = null;
  private backoffDelay = 1000;
  private maxBackoffDelay = 16000;
  private isIntentionalClose = false;
  private subscribersCount = 0;
  private reconnectAttempts = 0;

  // Deduplication cache to prevent duplicate events after reconnecting
  private seenEventKeys: Set<string> = new Set();
  private maxSeenKeys = 1000;

  public connect(): void {
    // Prevent duplicate connections if already open or connecting
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    this.isIntentionalClose = false;
    this.setStatus('reconnecting');

    try {
      // Determine WebSocket protocol and host
      const isHttps = typeof window !== 'undefined' && window.location.protocol === 'https:';
      const wsProtocol = isHttps ? 'wss:' : 'ws:';
      const host = typeof window !== 'undefined' && window.location.host ? window.location.host : 'localhost:3000';
      const token = (typeof localStorage !== 'undefined' && localStorage.getItem('sentinelx_token')) || 'demo-token';

      const wsUrl = `${wsProtocol}//${host}/api/v1/ws/events?token=${encodeURIComponent(token)}`;

      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        this.setStatus('connected');
        this.backoffDelay = 1000; // Reset backoff delay on successful connection
        this.reconnectAttempts = 0;
        this.cleanUpSSE(); // WebSocket active; clean up fallback SSE
        this.startHeartbeat();
      };

      this.ws.onmessage = (event) => {
        try {
          const raw = JSON.parse(event.data);

          // Handle system messages (pong / ack / subscribed)
          if (raw.type === 'pong' || raw.type === 'ack' || raw.type === 'subscribed') {
            return;
          }

          // Generate deduplication key
          const dedupeKey = this.generateDedupeKey(raw);
          if (dedupeKey && this.seenEventKeys.has(dedupeKey)) {
            // Duplicate detected after reconnect - ignore
            return;
          }
          if (dedupeKey) {
            if (this.seenEventKeys.size >= this.maxSeenKeys) {
              // Evict oldest entries
              const firstKey = this.seenEventKeys.values().next().value;
              if (firstKey) this.seenEventKeys.delete(firstKey);
            }
            this.seenEventKeys.add(dedupeKey);
          }

          // Normalize message for subscribers
          const normalized = {
            type: raw.type,
            timestamp: raw.timestamp || new Date().toISOString(),
            data: raw.data !== undefined ? raw.data : (raw.alert || raw.incident || raw.event || raw.host || raw),
            alert: raw.alert || (raw.type?.startsWith('alert') ? raw.data : undefined),
            incident: raw.incident || (raw.type?.startsWith('incident') ? raw.data : undefined),
            event: raw.event || (raw.type?.startsWith('event') ? raw.data : undefined),
            host: raw.host || (raw.type?.startsWith('host') ? raw.data : undefined),
          };

          this.listeners.forEach((callback) => {
            try {
              callback(normalized);
            } catch (err) {
              console.error('Realtime listener error:', err);
            }
          });
        } catch (err) {
          console.debug('Failed to parse WebSocket message:', err);
        }
      };

      this.ws.onerror = () => {
        console.debug('Realtime WebSocket error occurred, attempting recovery');
      };

      this.ws.onclose = () => {
        this.cleanUp();
        if (!this.isIntentionalClose && this.subscribersCount > 0) {
          this.setStatus('reconnecting');
          this.reconnectAttempts++;
          // If WebSocket has difficulty connecting, also activate SSE fallback
          if (this.reconnectAttempts >= 2) {
            this.tryFallbackSSE();
          }
          this.scheduleReconnect();
        } else {
          this.setStatus('disconnected');
        }
      };
    } catch (err) {
      console.warn('Failed to initialize WebSocket client, attempting fallback SSE:', err);
      this.tryFallbackSSE();
      this.scheduleReconnect();
    }
  }

  private tryFallbackSSE(): void {
    if (this.sse || this.status === 'connected') return;

    try {
      this.sse = new EventSource('/api/v1/ws/stream');

      this.sse.onopen = () => {
        this.setStatus('connected');
        this.backoffDelay = 1000;
      };

      this.sse.onmessage = (event) => {
        try {
          const raw = JSON.parse(event.data);
          const dedupeKey = this.generateDedupeKey(raw);
          if (dedupeKey && this.seenEventKeys.has(dedupeKey)) return;
          if (dedupeKey) this.seenEventKeys.add(dedupeKey);

          const normalized = {
            type: raw.type,
            timestamp: raw.timestamp || new Date().toISOString(),
            data: raw.data !== undefined ? raw.data : (raw.alert || raw.incident || raw.event || raw.host || raw),
            alert: raw.alert || (raw.type?.startsWith('alert') ? raw.data : undefined),
            incident: raw.incident || (raw.type?.startsWith('incident') ? raw.data : undefined),
            event: raw.event || (raw.type?.startsWith('event') ? raw.data : undefined),
            host: raw.host || (raw.type?.startsWith('host') ? raw.data : undefined),
          };

          this.listeners.forEach((callback) => callback(normalized));
        } catch (err) {
          console.debug('Failed to parse fallback SSE message:', err);
        }
      };

      this.sse.onerror = () => {
        this.cleanUpSSE();
      };
    } catch {
      // Ignore
    }
  }

  private generateDedupeKey(msg: any): string | null {
    if (!msg) return null;
    const type = msg.type || 'unknown';
    const id = msg.data?.id || msg.alert?.id || msg.incident?.id || msg.event?.id || msg.host?.id || msg.data?.event_id;
    if (id !== undefined) {
      return `${type}-${id}`;
    }
    if (msg.timestamp) {
      return `${type}-${msg.timestamp}`;
    }
    return null;
  }

  private startHeartbeat(): void {
    if (this.pingInterval) clearInterval(this.pingInterval);
    this.pingInterval = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        try {
          this.ws.send(JSON.stringify({ type: 'ping', timestamp: new Date().toISOString() }));
        } catch {
          // Ignore
        }
      }
    }, 20000);
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimeout) clearTimeout(this.reconnectTimeout);
    if (this.subscribersCount <= 0 && !this.isIntentionalClose) return;

    this.reconnectTimeout = setTimeout(() => {
      this.backoffDelay = Math.min(this.backoffDelay * 1.5, this.maxBackoffDelay);
      this.connect();
    }, this.backoffDelay);
  }

  private cleanUp(): void {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
    if (this.ws) {
      try {
        this.ws.onopen = null;
        this.ws.onmessage = null;
        this.ws.onerror = null;
        this.ws.onclose = null;
        this.ws.close();
      } catch {
        // Ignore
      }
      this.ws = null;
    }
  }

  private cleanUpSSE(): void {
    if (this.sse) {
      try {
        this.sse.close();
      } catch {
        // Ignore
      }
      this.sse = null;
    }
  }

  public disconnect(): void {
    this.isIntentionalClose = true;
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
    this.cleanUp();
    this.cleanUpSSE();
    this.setStatus('disconnected');
  }

  public incrementSubscribers(): void {
    this.subscribersCount++;
    this.connect();
  }

  public decrementSubscribers(): void {
    this.subscribersCount = Math.max(0, this.subscribersCount - 1);
    if (this.subscribersCount === 0) {
      this.disconnect();
    }
  }

  private setStatus(newStatus: RealtimeStatus): void {
    this.status = newStatus;
    this.statusListeners.forEach((fn) => fn(newStatus));
  }

  public getStatus(): RealtimeStatus {
    return this.status;
  }

  public subscribe(callback: RealtimeCallback): () => void {
    this.listeners.add(callback);
    return () => {
      this.listeners.delete(callback);
    };
  }

  public subscribeStatus(callback: (status: RealtimeStatus) => void): () => void {
    this.statusListeners.add(callback);
    callback(this.status);
    return () => {
      this.statusListeners.delete(callback);
    };
  }
}

export const realtimeClient = new RealtimeClient();

export function useRealtime(onMessage?: RealtimeCallback) {
  const [status, setStatus] = useState<RealtimeStatus>(realtimeClient.getStatus());
  const callbackRef = useRef(onMessage);
  callbackRef.current = onMessage;

  useEffect(() => {
    realtimeClient.incrementSubscribers();

    const unsubStatus = realtimeClient.subscribeStatus((newStatus) => {
      setStatus(newStatus);
    });

    const unsubMessage = realtimeClient.subscribe((data) => {
      if (callbackRef.current) {
        callbackRef.current(data);
      }
    });

    return () => {
      unsubStatus();
      unsubMessage();
      realtimeClient.decrementSubscribers();
    };
  }, []);

  const reconnect = useCallback(() => {
    realtimeClient.disconnect();
    realtimeClient.connect();
  }, []);

  return { status, reconnect };
}
