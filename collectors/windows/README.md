# SentinelX Windows Endpoint Collector (Phase 6)

A lightweight, defensive endpoint security telemetry collector designed for authorized Windows monitoring environments.

## 1. Features
- **Security Event Log**: Event IDs 4624 (Logon), 4625 (Failed Logon), 4672 (Privilege Assignment), 4688 (Process Creation)
- **PowerShell ScriptBlock**: Event IDs 4104 / 4103
- **Windows Defender**: Event IDs 1116 (Threat Detected), 1117 (Action Taken), 5001 (Tampering / Disabled)
- **Network Filtering Platform**: Event ID 5156 (Outbound Connections)
- **Zero Offensive Capabilities**: No persistence, no keylogging, no code injection, no process termination.
- **Safe Test Mode**: Generates synthetic laboratory telemetry (`--test-mode`) with explicit labeling.

## 2. Quick Start on Windows

### Prerequisites
- Python 3.10+ installed from python.org or Microsoft Store
- Network access to SentinelX SOC server (HTTP or HTTPS)

### Installation
```cmd
cd collectors\windows
pip install -r requirements.txt
```

### Running Test Mode
```cmd
python agent.py --test-mode --server-url http://localhost:3000 --collector-id win-workstation-01 --api-key <YOUR_COLLECTOR_KEY>
```

### Running as Continuous Monitoring Agent
```cmd
python agent.py --server-url https://soc.sentinelx.local --collector-id win-prod-dc01 --api-key <KEY>
```

## 3. Environment Variables
| Variable | Default | Description |
|---|---|---|
| `SENTINELX_SERVER_URL` | `http://localhost:3000` | Target SOC server base URL |
| `SENTINELX_COLLECTOR_ID` | `win-standalone-01` | Unique collector identifier |
| `SENTINELX_API_KEY` | (None) | Collector secret token |
| `SENTINELX_HEARTBEAT_INTERVAL` | `30.0` | Heartbeat interval (seconds) |
| `SENTINELX_POLL_INTERVAL` | `5.0` | Event poll interval (seconds) |
| `SENTINELX_BATCH_SIZE` | `25` | Maximum events per dispatch |
| `SENTINELX_BUFFER_MAX_SIZE` | `500` | Maximum queue size during network drop |
| `SENTINELX_TEST_MODE` | `false` | Enable synthetic telemetry generation |
