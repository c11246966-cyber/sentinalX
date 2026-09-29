"""HTTP/HTTPS telemetry transport client with bounded queue and retry logic."""

from collections import deque
import json
import time
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.request
from collectors.windows.config import WindowsCollectorConfig


class WindowsEventSender:
    """Delivers normalized telemetry events and heartbeats to SentinelX."""

    def __init__(self, config: WindowsCollectorConfig) -> None:
        self.config = config
        self.queue: deque = deque(maxlen=config.buffer_max_size)
        self._backoff_delay: float = 1.0
        self._consecutive_failures: int = 0
        self._last_heartbeat_time: float = 0.0

    def enqueue_event(self, event: Dict[str, Any]) -> bool:
        """Add normalized event to the bounded local memory queue."""
        if len(self.queue) >= self.config.buffer_max_size:
            # Drop oldest event to protect memory
            self.queue.popleft()
        self.queue.append(event)
        return True

    def flush_events(self) -> int:
        """Send all currently enqueued events to SentinelX in batches."""
        sent_count = 0
        while self.queue:
            batch: List[Dict[str, Any]] = []
            for _ in range(min(self.config.batch_size, len(self.queue))):
                if self.queue:
                    batch.append(self.queue.popleft())

            if not batch:
                break

            success = self._send_batch(batch)
            if success:
                sent_count += len(batch)
                self._backoff_delay = 1.0
                self._consecutive_failures = 0
            else:
                # Re-queue batch at left of queue and back off
                for item in reversed(batch):
                    self.queue.appendleft(item)
                self._consecutive_failures += 1
                self._backoff_delay = min(30.0, self._backoff_delay * 2.0)
                time.sleep(self._backoff_delay)
                break

        return sent_count

    def _send_batch(self, events: List[Dict[str, Any]]) -> bool:
        """Send a single batch or single events via HTTP POST to /api/v1/events/ingest."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SentinelX-Windows-Collector/1.0",
            "X-Collector-ID": self.config.collector_id,
        }
        if self.config.api_key:
            headers["X-Collector-Key"] = self.config.api_key

        url = self.config.get_ingest_url()

        for event in events:
            payload_bytes = json.dumps(event).encode("utf-8")
            req = urllib.request.Request(url, data=payload_bytes, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.config.request_timeout) as resp:
                    if resp.status not in (200, 201):
                        return False
            except Exception:
                return False

        return True

    def send_heartbeat(self, status: str = "ONLINE", stats: Optional[Dict[str, Any]] = None) -> bool:
        """Send heartbeat ping to SentinelX."""
        url = self.config.get_heartbeat_url()
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SentinelX-Windows-Collector/1.0",
            "X-Collector-ID": self.config.collector_id,
        }
        if self.config.api_key:
            headers["X-Collector-Key"] = self.config.api_key

        payload = {
            "status": status,
            "telemetry_stats": stats or {"queue_size": len(self.queue)},
        }
        payload_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=payload_bytes, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.config.request_timeout) as resp:
                if resp.status in (200, 201):
                    self._last_heartbeat_time = time.time()
                    return True
        except Exception:
            pass

        return False
