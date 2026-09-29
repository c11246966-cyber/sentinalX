"""Safe host system telemetry gathering for Windows agent."""

import os
import platform
import socket
import time
from typing import Any, Dict


def get_host_telemetry() -> Dict[str, Any]:
    """Collect safe defensive metadata about the current Windows host.
    
    Collects only system metrics necessary for endpoint identification and agent health.
    Never collects user documents, credentials, or private keys.
    """
    hostname = socket.gethostname()
    
    # Try resolving primary IPv4 address
    ip_address = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
    except Exception:
        try:
            ip_address = socket.gethostbyname(hostname)
        except Exception:
            pass

    return {
        "hostname": hostname,
        "ip_address": ip_address,
        "operating_system": f"{platform.system()} {platform.release()}",
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "agent_version": "1.0.0",
        "cpu_count": os.cpu_count() or 1,
        "timestamp": time.time(),
    }
