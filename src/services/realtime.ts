import { useEffect, useState, useRef, useCallback } from 'react';
import { RealtimeStatus } from '../types';

type RealtimeCallback = (data: any) => void;

class RealtimeClient {
  private eventSource: EventSource | null = null;
  private listeners: Set<RealtimeCallback> = new Set();
  private statusListeners: Set<(status: RealtimeStatus) => void> = new Set();
  private status: RealtimeStatus = 'disconnected';
  private reconnectTimeout: any = null;
  private backoffDelay = 1000;
  private maxBackoffDelay = 16000;
  private isIntentionalClose = false;

  public connect(): void {
    if (this.eventSource || this.status === 'connected') return;

    this.isIntentionalClose = false;
    this.setStatus('reconnecting');

    try {
      // Connect to SSE endpoint (no tokens exposed in URL)
      this.eventSource = new EventSource('/api/v1/ws/stream');

      this.eventSource.onopen = () => {
        this.setStatus('connected');
        this.backoffDelay = 1000; // Reset backoff on success
      };

      this.eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          this.listeners.forEach((callback) => callback(data));
        } catch (err) {
          console.debug('Failed to parse SSE message:', err);
        }
      };

      this.eventSource.onerror = () => {
        this.cleanUp();
        if (!this.isIntentionalClose) {
          this.setStatus('reconnecting');
          this.scheduleReconnect();
        } else {
          this.setStatus('disconnected');
        }
      };
    } catch (err) {
      console.error('Failed to initialize EventSource:', err);
      this.setStatus('disconnected');
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimeout) clearTimeout(this.reconnectTimeout);
    this.reconnectTimeout = setTimeout(() => {
      this.backoffDelay = Math.min(this.backoffDelay * 2, this.maxBackoffDelay);
      this.connect();
    }, this.backoffDelay);
  }

  private cleanUp(): void {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
  }

  public disconnect(): void {
    this.isIntentionalClose = true;
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
    this.cleanUp();
    this.setStatus('disconnected');
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
    realtimeClient.connect();

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
    };
  }, []);

  const reconnect = useCallback(() => {
    realtimeClient.disconnect();
    realtimeClient.connect();
  }, []);

  return { status, reconnect };
}
