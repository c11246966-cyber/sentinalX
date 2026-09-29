"""SentinelX Windows Endpoint Telemetry Collector Agent CLI."""

import argparse
import logging
import sys
import time
from collectors.windows.config import WindowsCollectorConfig
from collectors.windows.event_reader import WindowsEventReader
from collectors.windows.health import get_host_telemetry
from collectors.windows.normalizer import WindowsEventNormalizer
from collectors.windows.sender import WindowsEventSender

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [SentinelX-WinAgent] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("sentinelx_win_agent")


def run_agent(args):
    config = WindowsCollectorConfig()
    if args.test_mode:
        config.test_mode = True
    if args.server_url:
        config.server_url = args.server_url.rstrip("/")
    if args.collector_id:
        config.collector_id = args.collector_id
    if args.api_key:
        config.api_key = args.api_key

    logger.info("Initializing SentinelX Windows Telemetry Collector v1.0.0")
    logger.info(f"Target SentinelX Server: {config.server_url}")
    logger.info(f"Collector ID: {config.collector_id}")
    logger.info(f"Test Mode: {'ENABLED (Synthetic Lab Telemetry)' if config.test_mode else 'DISABLED (Live Windows Security Log)'}")

    host_meta = get_host_telemetry()
    hostname = host_meta.get("hostname", "WINDOWS-HOST")
    logger.info(f"Host System: {hostname} ({host_meta.get('operating_system')})")

    reader = WindowsEventReader(hostname=hostname, test_mode=config.test_mode)
    sender = WindowsEventSender(config=config)

    # 1. Send initial heartbeat
    logger.info("Sending initial agent check-in heartbeat...")
    hb_success = sender.send_heartbeat(status="ONLINE", stats=host_meta)
    if hb_success:
        logger.info("Check-in heartbeat accepted by SentinelX.")
    else:
        logger.warning("Heartbeat response was not 200/201. Will retry during execution loop.")

    if args.heartbeat_only:
        logger.info("Heartbeat completed. Exiting as requested by --heartbeat-only.")
        return 0

    # Event collection cycle
    total_events_sent = 0
    last_hb_time = time.time()

    def process_cycle() -> int:
        raw_events = reader.read_events(max_records=config.batch_size)
        enqueued = 0
        for raw in raw_events:
            norm = WindowsEventNormalizer.normalize_event(
                raw_event=raw,
                default_hostname=hostname,
                is_test_mode=config.test_mode,
            )
            sender.enqueue_event(norm)
            enqueued += 1

        flushed = sender.flush_events()
        logger.info(f"Ingested {enqueued} events; dispatched {flushed} normalized events to SentinelX.")
        return flushed

    if args.once or config.test_mode:
        total_events_sent = process_cycle()
        logger.info(f"Completed single collection cycle. Total events dispatched: {total_events_sent}")
        return 0

    # Daemon loop
    logger.info("Entering continuous telemetry monitoring daemon loop (Ctrl+C to stop)...")
    try:
        while True:
            total_events_sent += process_cycle()

            now = time.time()
            if now - last_hb_time >= config.heartbeat_interval:
                sender.send_heartbeat(status="ONLINE", stats={"total_sent": total_events_sent})
                last_hb_time = now

            time.sleep(config.poll_interval)
    except KeyboardInterrupt:
        logger.info("Graceful collector shutdown requested by operator.")
        sender.send_heartbeat(status="OFFLINE")

    return 0


def main():
    parser = argparse.ArgumentParser(description="SentinelX Windows Endpoint Telemetry Collector")
    parser.add_argument("--test-mode", action="store_true", help="Generate safe synthetic Windows telemetry without live Event Log")
    parser.add_argument("--heartbeat-only", action="store_true", help="Send a single check-in heartbeat and exit")
    parser.add_argument("--once", action="store_true", help="Collect and send events once, then exit")
    parser.add_argument("--server-url", type=str, help="SentinelX API server base URL")
    parser.add_argument("--collector-id", type=str, help="Assigned collector identifier")
    parser.add_argument("--api-key", type=str, help="Secret collector authorization key")
    args = parser.parse_args()

    sys.exit(run_agent(args))


if __name__ == "__main__":
    main()
