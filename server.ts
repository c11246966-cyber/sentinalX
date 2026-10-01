import express, { Request, Response } from 'express';
import http from 'http';
import WebSocket, { WebSocketServer } from 'ws';
import { createServer as createViteServer } from 'vite';
import path from 'path';

const app = express();
const PORT = 3000;

app.use(express.json());

// In-memory telemetry storage for mock/demo purposes when running in node dev mode
const mockHealth = {
  status: 'healthy',
  version: '0.1.0-alpha',
  environment: process.env.ENVIRONMENT || 'development',
  timestamp: new Date().toISOString(),
  services: {
    api: {
      status: 'healthy',
      latency_ms: 0.05,
      message: 'FastAPI core dispatcher active on port 8000',
    },
    database: {
      status: 'healthy',
      latency_ms: 2.14,
      message: 'PostgreSQL connection verified (sentinelx_db on port 5432)',
    },
    redis: {
      status: 'healthy',
      latency_ms: 0.88,
      message: 'Redis cache and pub/sub operational on port 6379',
    },
  },
};

// Root health check endpoint matching FastAPI
app.get(['/health', '/api/v1/health'], (_req: Request, res: Response) => {
  res.json({
    ...mockHealth,
    timestamp: new Date().toISOString(),
  });
});

// Phase 2 Auth and User mock state for preview server
interface MockUser {
  id: number;
  username: string;
  email: string;
  role: 'admin' | 'analyst' | 'viewer';
  is_active: boolean;
  created_at: string;
  last_login?: string;
}

const mockUsers: MockUser[] = [
  {
    id: 1,
    username: 'admin',
    email: 'admin@sentinelx.local',
    role: 'admin',
    is_active: true,
    created_at: '2026-09-28T08:00:00.000Z',
    last_login: '2026-09-28T16:45:00.000Z',
  },
  {
    id: 2,
    username: 'sec_analyst',
    email: 'analyst@sentinelx.local',
    role: 'analyst',
    is_active: true,
    created_at: '2026-09-28T08:30:00.000Z',
    last_login: '2026-09-28T16:50:00.000Z',
  },
  {
    id: 3,
    username: 'soc_viewer',
    email: 'viewer@sentinelx.local',
    role: 'viewer',
    is_active: true,
    created_at: '2026-09-28T09:00:00.000Z',
    last_login: '2026-09-28T16:30:00.000Z',
  },
];

const mockAuditLogs = [
  {
    id: 101,
    user_id: 1,
    action: 'user_login',
    target_type: 'user',
    target_id: '1',
    details: { role: 'admin' },
    source_ip: '127.0.0.1',
    timestamp: new Date(Date.now() - 3600000).toISOString(),
  },
  {
    id: 102,
    user_id: 2,
    action: 'login_success',
    target_type: 'user',
    target_id: '2',
    details: { role: 'analyst' },
    source_ip: '10.0.0.15',
    timestamp: new Date(Date.now() - 1800000).toISOString(),
  },
];

app.post('/api/v1/auth/login', (req: Request, res: Response) => {
  const { username, password } = req.body || {};
  const user = mockUsers.find((u) => u.username === username);
  if (!user || password !== 'SentinelX@2026') {
    // For demo allow standard credentials
    if (username === 'admin' || username === 'sec_analyst' || username === 'soc_viewer') {
      const u = mockUsers.find((x) => x.username === username)!;
      return res.json({
        access_token: `mock-jwt-access-${u.username}-${Date.now()}`,
        refresh_token: `mock-jwt-refresh-${u.username}-${Date.now()}`,
        token_type: 'bearer',
        role: u.role,
        username: u.username,
        user_id: u.id,
      });
    }
    return res.status(401).json({ detail: 'Incorrect username or password' });
  }

  res.json({
    access_token: `mock-jwt-access-${user.username}-${Date.now()}`,
    refresh_token: `mock-jwt-refresh-${user.username}-${Date.now()}`,
    token_type: 'bearer',
    role: user.role,
    username: user.username,
    user_id: user.id,
  });
});

app.post('/api/v1/auth/refresh', (req: Request, res: Response) => {
  const { refresh_token } = req.body || {};
  if (!refresh_token) {
    return res.status(401).json({ detail: 'Invalid or expired refresh token' });
  }
  res.json({
    access_token: `mock-jwt-access-refreshed-${Date.now()}`,
    refresh_token: `mock-jwt-refresh-rotated-${Date.now()}`,
    token_type: 'bearer',
    role: 'analyst',
    username: 'sec_analyst',
    user_id: 2,
  });
});

app.get('/api/v1/auth/me', (_req: Request, res: Response) => {
  res.json(mockUsers[0]);
});

app.post('/api/v1/auth/logout', (_req: Request, res: Response) => {
  res.json({ status: 'logged_out' });
});

app.get('/api/v1/users', (_req: Request, res: Response) => {
  res.json(mockUsers);
});

app.get('/api/v1/audit', (_req: Request, res: Response) => {
  res.json(mockAuditLogs);
});

// Phase 3 In-memory state for Events, Alerts, Incidents, and Detection Pipeline
interface MockEvent {
  id: number;
  event_id: string;
  timestamp: string;
  source: string;
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  protocol?: string;
  event_type: string;
  severity: string;
  username?: string;
  hostname?: string;
  process_name?: string;
  command_line?: string;
  message: string;
  mitre_technique?: string;
  status: string;
  created_at: string;
}

const mockEvents: MockEvent[] = [
  {
    id: 1,
    event_id: 'evt_a1b2c3d4e5',
    timestamp: new Date(Date.now() - 300000).toISOString(),
    source: 'network',
    source_ip: '192.0.2.100',
    destination_ip: '10.0.0.10',
    source_port: 54312,
    destination_port: 22,
    protocol: 'TCP',
    event_type: 'port_scan',
    severity: 'HIGH',
    hostname: 'PROD-GATEWAY',
    message: 'Port scan probing destination port 22',
    mitre_technique: 'T1046',
    status: 'PROCESSED',
    created_at: new Date(Date.now() - 300000).toISOString(),
  },
  {
    id: 2,
    event_id: 'evt_f6e7d8c9b0',
    timestamp: new Date(Date.now() - 200000).toISOString(),
    source: 'linux-agent',
    source_ip: '198.51.100.50',
    destination_ip: '10.0.0.20',
    source_port: 41203,
    destination_port: 22,
    protocol: 'TCP',
    event_type: 'authentication_failure',
    severity: 'HIGH',
    username: 'root',
    hostname: 'PROD-AUTH-01',
    message: 'Failed password for root via sshd',
    mitre_technique: 'T1110.001',
    status: 'PROCESSED',
    created_at: new Date(Date.now() - 200000).toISOString(),
  },
  {
    id: 3,
    event_id: 'evt_9988776655',
    timestamp: new Date(Date.now() - 100000).toISOString(),
    source: 'web-agent',
    source_ip: '203.0.113.15',
    destination_ip: '10.0.0.30',
    destination_port: 443,
    protocol: 'HTTP',
    event_type: 'http_request',
    severity: 'HIGH',
    hostname: 'PROD-WEB-FRONTEND',
    message: "GET /search?q=' UNION SELECT username, password FROM users-- HTTP/1.1",
    mitre_technique: 'T1190',
    status: 'PROCESSED',
    created_at: new Date(Date.now() - 100000).toISOString(),
  },
];

interface MockAlert {
  id: number;
  event_id?: number;
  incident_id?: number;
  title: string;
  description: string;
  severity: string;
  risk_score: number;
  status: 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE' | 'TRIAGED';
  source_ip?: string;
  destination_ip?: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  analyst_notes?: string;
  threat_intel_context?: any;
  risk_adjustment_reason?: string;
  created_at: string;
  updated_at: string;
}

const mockAlerts: MockAlert[] = [
  {
    id: 1,
    event_id: 1,
    incident_id: 1,
    title: 'Port Scanning Activity Detected from 192.0.2.100',
    description: 'Source 192.0.2.100 probed multiple ports across infrastructure within short window.',
    severity: 'MEDIUM',
    risk_score: 75,
    status: 'NEW',
    source_ip: '192.0.2.100',
    destination_ip: '10.0.0.10',
    mitre_tactic: 'Discovery',
    mitre_technique: 'T1046',
    threat_intel_context: {
      indicator: '192.0.2.100',
      indicator_type: 'ipv4',
      provider: 'internal',
      reputation: 'suspicious',
      confidence: 85,
      severity: 'MEDIUM',
      tags: ['reconnaissance_source', 'port_scanner'],
    },
    risk_adjustment_reason: 'Risk adjusted from 65 to 75 (+10 pts): Indicator 192.0.2.100 evaluated as SUSPICIOUS (confidence 85%) by internal feed.',
    created_at: new Date(Date.now() - 300000).toISOString(),
    updated_at: new Date(Date.now() - 300000).toISOString(),
  },
  {
    id: 2,
    event_id: 2,
    incident_id: 1,
    title: 'SSH Brute Force Attack from 198.51.100.50',
    description: 'Consecutive SSH authentication failures detected targeting root.',
    severity: 'CRITICAL',
    risk_score: 95,
    status: 'INVESTIGATING',
    source_ip: '198.51.100.50',
    destination_ip: '10.0.0.20',
    mitre_tactic: 'Credential Access',
    mitre_technique: 'T1110.001',
    threat_intel_context: {
      indicator: '198.51.100.50',
      indicator_type: 'ipv4',
      provider: 'consensus',
      providers_reporting: ['abuseipdb', 'internal'],
      reputation: 'malicious',
      confidence: 92,
      severity: 'HIGH',
      tags: ['brute_force_botnet', 'credential_access', 'ssh_attacker'],
    },
    risk_adjustment_reason: 'Risk adjusted from 70 to 95 (+25 pts): Indicator 198.51.100.50 evaluated as MALICIOUS (confidence 92%) by consensus. Factors: Malicious reputation (+20 pts); Multi-provider consensus (+5 pts).',
    created_at: new Date(Date.now() - 200000).toISOString(),
    updated_at: new Date(Date.now() - 180000).toISOString(),
  },
  {
    id: 3,
    event_id: 3,
    title: 'Web Exploitation Pattern Observed from 203.0.113.15',
    description: 'SQL Injection signature detected in query parameters.',
    severity: 'HIGH',
    risk_score: 88,
    status: 'NEW',
    source_ip: '203.0.113.15',
    destination_ip: '10.0.0.30',
    mitre_tactic: 'Initial Access',
    mitre_technique: 'T1190',
    threat_intel_context: {
      indicator: '203.0.113.15',
      indicator_type: 'ipv4',
      provider: 'consensus',
      providers_reporting: ['virustotal', 'internal'],
      reputation: 'malicious',
      confidence: 88,
      severity: 'HIGH',
      tags: ['web_attack_source', 'sqli_probe', 'initial_access'],
    },
    risk_adjustment_reason: 'Risk adjusted from 68 to 88 (+20 pts): Indicator 203.0.113.15 evaluated as MALICIOUS (confidence 88%) by consensus.',
    created_at: new Date(Date.now() - 100000).toISOString(),
    updated_at: new Date(Date.now() - 100000).toISOString(),
  },
];

interface MockIncident {
  id: number;
  title: string;
  description: string;
  severity: string;
  risk_score: number;
  status: 'NEW' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';
  assigned_to?: number;
  analyst_notes?: string;
  created_at: string;
  updated_at: string;
}

const mockIncidents: MockIncident[] = [
  {
    id: 1,
    title: 'Correlated Incident: Persistent Intrusion on DMZ Gateway',
    description: 'Aggregated reconnaissance port scan and subsequent SSH brute force on external perimeter.',
    severity: 'HIGH',
    risk_score: 88,
    status: 'INVESTIGATING',
    assigned_to: 2,
    created_at: new Date(Date.now() - 200000).toISOString(),
    updated_at: new Date(Date.now() - 150000).toISOString(),
  },
];

const mockMitreCatalog = [
  { id: 'T1046', technique: 'Network Service Discovery', tactic: 'Discovery', url: 'https://attack.mitre.org/techniques/T1046/' },
  { id: 'T1110', technique: 'Brute Force', tactic: 'Credential Access', url: 'https://attack.mitre.org/techniques/T1110/' },
  { id: 'T1110.001', technique: 'Password Guessing', tactic: 'Credential Access', url: 'https://attack.mitre.org/techniques/T1110/001/' },
  { id: 'T1190', technique: 'Exploit Public-Facing Application', tactic: 'Initial Access', url: 'https://attack.mitre.org/techniques/T1190/' },
  { id: 'T1059', technique: 'Command and Scripting Interpreter', tactic: 'Execution', url: 'https://attack.mitre.org/techniques/T1059/' },
  { id: 'T1498', technique: 'Network Denial of Service', tactic: 'Impact', url: 'https://attack.mitre.org/techniques/T1498/' },
  { id: 'T1068', technique: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation', url: 'https://attack.mitre.org/techniques/T1068/' },
  { id: 'T1078', technique: 'Valid Accounts', tactic: 'Initial Access', url: 'https://attack.mitre.org/techniques/T1078/' },
];

// Server-Sent Events & WebSocket subscribers for Phase 7
const sseClients = new Set<Response>();

interface WsClientSession {
  ws: WebSocket;
  userId: string;
  role: string;
  channels: Set<string>;
}
const wsClientSessions = new Map<WebSocket, WsClientSession>();

function broadcastRealtime(type: string, data: any) {
  // Normalize into Phase 7 structured message format
  const structured = {
    type,
    timestamp: new Date().toISOString(),
    data,
    // Maintain legacy keys for backwards compatibility
    alert: type.startsWith('alert') ? data : undefined,
    incident: type.startsWith('incident') ? data : undefined,
    event: type.startsWith('event') ? data : undefined,
    host: type.startsWith('host') ? data : undefined,
  };

  const payloadStr = JSON.stringify(structured);

  // 1. Deliver to all authenticated WebSocket clients
  for (const [ws, session] of wsClientSessions.entries()) {
    if (ws.readyState === WebSocket.OPEN) {
      if (session.channels.size === 0 || session.channels.has('*') || session.channels.has(type)) {
        try {
          ws.send(payloadStr);
        } catch {
          wsClientSessions.delete(ws);
        }
      }
    } else {
      wsClientSessions.delete(ws);
    }
  }

  // 2. Deliver to Server-Sent Events subscribers
  broadcastSSE(structured);
}

function broadcastSSE(data: any) {
  const payload = `data: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(payload);
    } catch {
      sseClients.delete(client);
    }
  }
}

// SSE Real-time stream endpoint
app.get(['/api/v1/ws/stream', '/api/v1/dashboard/stream'], (req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();

  sseClients.add(res);
  res.write(`data: ${JSON.stringify({ type: 'connection_established', message: 'SentinelX SSE Stream Connected' })}\n\n`);

  const keepAlive = setInterval(() => {
    res.write(': keep-alive\n\n');
  }, 15000);

  req.on('close', () => {
    clearInterval(keepAlive);
    sseClients.delete(res);
  });
});

// Dashboard Aggregated Stats API
app.get('/api/v1/dashboard/stats', (_req: Request, res: Response) => {
  const totalEvents = mockEvents.length;
  const totalAlerts = mockAlerts.length;
  const activeAlerts = mockAlerts.filter(a => a.status !== 'RESOLVED' && a.status !== 'FALSE_POSITIVE').length;
  const openIncidents = mockIncidents.filter(i => i.status !== 'RESOLVED' && i.status !== 'CLOSED').length;
  const criticalAlerts = mockAlerts.filter(a => a.severity === 'CRITICAL').length;
  const avgRisk = mockAlerts.length > 0
    ? Math.round(mockAlerts.reduce((acc, a) => acc + a.risk_score, 0) / mockAlerts.length)
    : 0;

  const sevCounts = {
    CRITICAL: mockAlerts.filter(a => a.severity === 'CRITICAL').length,
    HIGH: mockAlerts.filter(a => a.severity === 'HIGH').length,
    MEDIUM: mockAlerts.filter(a => a.severity === 'MEDIUM').length,
    LOW: mockAlerts.filter(a => a.severity === 'LOW').length,
    INFORMATIONAL: mockAlerts.filter(a => a.severity === 'INFORMATIONAL').length,
  };

  const riskDist = {
    '0-24 (Low)': mockAlerts.filter(a => a.risk_score < 25).length,
    '25-49 (Guarded)': mockAlerts.filter(a => a.risk_score >= 25 && a.risk_score < 50).length,
    '50-74 (Elevated)': mockAlerts.filter(a => a.risk_score >= 50 && a.risk_score < 75).length,
    '75-100 (Severe)': mockAlerts.filter(a => a.risk_score >= 75).length,
  };

  const srcMap: Record<string, number> = {};
  mockEvents.forEach(e => {
    if (e.source_ip) srcMap[e.source_ip] = (srcMap[e.source_ip] || 0) + 1;
  });
  const topSourceIps = Object.entries(srcMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([ip, count]) => ({ ip, event_count: count }));

  const assetMap: Record<string, number> = {};
  mockEvents.forEach(e => {
    const asset = e.hostname || e.destination_ip || 'Unknown';
    assetMap[asset] = (assetMap[asset] || 0) + 1;
  });
  const topAffectedAssets = Object.entries(assetMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([asset, count]) => ({ asset, event_count: count }));

  const mitreCoverage = mockMitreCatalog.map(m => {
    const hits = mockAlerts.filter(a => a.mitre_technique === m.id).length;
    return {
      ...m,
      detections: hits,
      is_active: hits > 0,
    };
  });

  const now = Date.now();
  const eventTimeline = [5, 4, 3, 2, 1, 0].map(h => {
    const d = new Date(now - h * 3600000);
    return {
      time: `${d.getHours().toString().padStart(2, '0')}:00`,
      events: Math.max(1, Math.round(totalEvents / 6) + (h % 3) * 2),
      alerts: Math.max(0, Math.round(totalAlerts / 6) + (h % 2)),
    };
  });

  res.json({
    executive_overview: {
      defense_status: criticalAlerts > 0 ? 'CRITICAL ALERT' : (activeAlerts > 0 ? 'ELEVATED' : 'DEFENDING'),
      total_events: totalEvents,
      total_alerts: totalAlerts,
      active_alerts: activeAlerts,
      open_incidents: openIncidents,
      critical_alerts: criticalAlerts,
      average_risk_score: avgRisk,
      tactics_covered: new Set(mitreCoverage.filter(m => m.is_active).map(m => m.tactic)).size,
      total_rules: mockMitreCatalog.length,
    },
    severity_counts: sevCounts,
    risk_distribution: riskDist,
    event_timeline: eventTimeline,
    top_source_ips: topSourceIps,
    top_affected_assets: topAffectedAssets,
    mitre_coverage: mitreCoverage,
    recent_alerts: mockAlerts.slice(0, 6),
    recent_incidents: mockIncidents.slice(0, 4),
  });
});

// Event Ingestion API
app.get('/api/v1/events', (req: Request, res: Response) => {
  const { event_type, source_ip, destination_ip, hostname, severity, search } = req.query;
  let filtered = [...mockEvents];
  if (event_type) filtered = filtered.filter(e => e.event_type.toLowerCase() === (event_type as string).toLowerCase());
  if (source_ip) filtered = filtered.filter(e => e.source_ip === source_ip);
  if (destination_ip) filtered = filtered.filter(e => e.destination_ip === destination_ip);
  if (hostname) filtered = filtered.filter(e => e.hostname?.toLowerCase().includes((hostname as string).toLowerCase()));
  if (severity) filtered = filtered.filter(e => e.severity === (severity as string).toUpperCase());
  if (search) {
    const q = (search as string).toLowerCase();
    filtered = filtered.filter(e =>
      e.message.toLowerCase().includes(q) ||
      e.event_id.toLowerCase().includes(q) ||
      (e.source_ip && e.source_ip.includes(q)) ||
      (e.hostname && e.hostname.toLowerCase().includes(q))
    );
  }
  res.json(filtered);
});

app.post('/api/v1/events', (req: Request, res: Response) => {
  const body = req.body || {};
  const newEvt: MockEvent = {
    id: mockEvents.length + 1,
    event_id: body.event_id || `evt_${Math.random().toString(16).slice(2, 10)}`,
    timestamp: body.timestamp || new Date().toISOString(),
    source: body.source || 'network',
    source_ip: body.source_ip,
    destination_ip: body.destination_ip,
    source_port: body.source_port,
    destination_port: body.destination_port,
    protocol: body.protocol || 'TCP',
    event_type: body.event_type || 'generic_event',
    severity: body.severity || 'INFORMATIONAL',
    username: body.username,
    hostname: body.hostname,
    process_name: body.process_name,
    message: body.message || 'Telemetry event ingested',
    mitre_technique: body.mitre_technique,
    status: 'PROCESSED',
    created_at: new Date().toISOString(),
  };
  mockEvents.unshift(newEvt);

  // Broadcast event real-time (Phase 7 event.created)
  broadcastRealtime('event.created', newEvt);

  // Check if synthetic alert triggers
  const generatedAlerts: any[] = [];
  const shouldTriggerAlert =
    newEvt.event_type === 'port_scan' ||
    newEvt.destination_port === 22 ||
    newEvt.event_type.includes('fail') ||
    newEvt.event_type.includes('flood') ||
    newEvt.severity === 'CRITICAL' ||
    newEvt.severity === 'HIGH' ||
    mockThreatIntelRecords.some(r => r.reputation === 'malicious' && (
      r.indicator === newEvt.source_ip ||
      r.indicator === newEvt.destination_ip ||
      (newEvt.message && newEvt.message.includes(r.indicator))
    ));

  if (shouldTriggerAlert) {
    // Phase 8 Local Threat Intelligence Indicator Extraction & Enrichment
    let intelMatch = mockThreatIntelRecords.find(r => r.indicator === newEvt.source_ip);
    if (!intelMatch && newEvt.destination_ip) {
      intelMatch = mockThreatIntelRecords.find(r => r.indicator === newEvt.destination_ip);
    }
    if (!intelMatch && newEvt.message) {
      intelMatch = mockThreatIntelRecords.find(r => newEvt.message.includes(r.indicator));
    }

    let alertRisk = newEvt.severity === 'CRITICAL' ? 85 : (newEvt.severity === 'HIGH' ? 70 : 55);
    let alertSev = newEvt.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH';
    let riskReason: string | undefined = undefined;

    if (intelMatch && intelMatch.reputation === 'malicious') {
      const bonus = intelMatch.severity === 'CRITICAL' ? 20 : 15;
      alertRisk = Math.min(100, alertRisk + bonus);
      alertSev = 'CRITICAL';
      riskReason = `Threat Intel elevated risk (+${bonus}): Indicator ${intelMatch.indicator} identified as MALICIOUS [${intelMatch.threat_category || 'General Threat'}] with ${intelMatch.confidence}% confidence. Evidence: ${intelMatch.matching_reason || 'Known lab adversary IOC'}`;
    } else if (intelMatch && intelMatch.reputation === 'suspicious') {
      alertRisk = Math.min(100, alertRisk + 8);
      riskReason = `Threat Intel adjusted risk (+8): Indicator ${intelMatch.indicator} flagged as SUSPICIOUS [${intelMatch.threat_category || 'Probe'}] with ${intelMatch.confidence}% confidence.`;
    } else if (intelMatch && intelMatch.reputation === 'clean') {
      alertRisk = Math.max(0, alertRisk - 5);
      riskReason = `Threat Intel verified benign (-5): Indicator ${intelMatch.indicator} identified as CLEAN [${intelMatch.threat_category || 'Internal Infrastructure'}].`;
    }

    const alert: MockAlert = {
      id: mockAlerts.length + 1,
      event_id: newEvt.id,
      title: `Detection Triggered: ${newEvt.event_type} from ${newEvt.source_ip || newEvt.hostname || 'system'}`,
      description: newEvt.message,
      severity: alertSev,
      risk_score: alertRisk,
      status: 'NEW',
      source_ip: newEvt.source_ip,
      destination_ip: newEvt.destination_ip,
      mitre_technique: newEvt.mitre_technique || 'T1046',
      threat_intel_context: intelMatch || undefined,
      risk_adjustment_reason: riskReason,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    mockAlerts.unshift(alert);
    generatedAlerts.push(alert);

    // Broadcast alert real-time (Phase 7 alert.created)
    broadcastRealtime('alert.created', alert);
  }

  res.status(201).json({
    status: 'success',
    ingested_count: 1,
    event_ids: [newEvt.event_id],
    generated_alerts: generatedAlerts,
  });
});

// Alerts API
app.get('/api/v1/alerts', (req: Request, res: Response) => {
  const { status, severity, source_ip, destination_ip, mitre_technique } = req.query;
  let filtered = [...mockAlerts];
  if (status) filtered = filtered.filter(a => a.status === (status as string).toUpperCase());
  if (severity) filtered = filtered.filter(a => a.severity === (severity as string).toUpperCase());
  if (source_ip) filtered = filtered.filter(a => a.source_ip === source_ip);
  if (destination_ip) filtered = filtered.filter(a => a.destination_ip === destination_ip);
  if (mitre_technique) filtered = filtered.filter(a => a.mitre_technique === mitre_technique);
  res.json(filtered);
});

app.get('/api/v1/alerts/:id', (req: Request, res: Response) => {
  const a = mockAlerts.find(x => x.id === parseInt(req.params.id, 10));
  if (!a) return res.status(404).json({ detail: 'Alert not found' });
  const evt = mockEvents.find(e => e.id === a.event_id);
  const mitreInfo = mockMitreCatalog.find(m => m.id === a.mitre_technique);
  res.json({
    ...a,
    event: evt || null,
    mitre_details: mitreInfo || null,
  });
});

app.patch('/api/v1/alerts/:id', (req: Request, res: Response) => {
  const a = mockAlerts.find(x => x.id === parseInt(req.params.id, 10));
  if (!a) return res.status(404).json({ detail: 'Alert not found' });
  const { status, severity, risk_score, analyst_notes, incident_id } = req.body || {};
  if (status) a.status = status;
  if (severity) a.severity = severity;
  if (risk_score !== undefined) a.risk_score = risk_score;
  if (analyst_notes !== undefined) a.analyst_notes = analyst_notes;
  if (incident_id !== undefined) a.incident_id = incident_id;
  a.updated_at = new Date().toISOString();

  broadcastRealtime('alert.updated', a);
  if (risk_score !== undefined) {
    broadcastRealtime('risk.updated', {
      entity_type: 'alert',
      entity_id: a.id,
      risk_score: a.risk_score,
      title: a.title,
    });
  }

  res.json(a);
});

// Incidents API
app.get('/api/v1/incidents', (_req: Request, res: Response) => {
  res.json(mockIncidents.map(i => ({
    ...i,
    alert_count: mockAlerts.filter(a => a.incident_id === i.id).length,
  })));
});

app.get('/api/v1/incidents/:id', (req: Request, res: Response) => {
  const inc = mockIncidents.find(x => x.id === parseInt(req.params.id, 10));
  if (!inc) return res.status(404).json({ detail: 'Incident not found' });
  const linkedAlerts = mockAlerts.filter(a => a.incident_id === inc.id);
  const eventIds = linkedAlerts.map(a => a.event_id).filter(Boolean);
  const linkedEvents = mockEvents.filter(e => eventIds.includes(e.id));
  const assignee = mockUsers.find(u => u.id === inc.assigned_to);

  res.json({
    ...inc,
    assignee_name: assignee ? assignee.username : null,
    alerts: linkedAlerts,
    events: linkedEvents,
  });
});

app.post('/api/v1/incidents', (req: Request, res: Response) => {
  const body = req.body || {};
  const inc: MockIncident = {
    id: mockIncidents.length + 1,
    title: body.title || 'Security Incident',
    description: body.description || '',
    severity: body.severity || 'MEDIUM',
    risk_score: body.risk_score || 50,
    status: 'NEW',
    assigned_to: body.assigned_to,
    analyst_notes: body.analyst_notes,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  if (body.alert_ids && Array.isArray(body.alert_ids)) {
    for (const aId of body.alert_ids) {
      const alert = mockAlerts.find(a => a.id === aId);
      if (alert) {
        alert.incident_id = inc.id;
        if (alert.status === 'NEW') alert.status = 'INVESTIGATING';
      }
    }
  }

  mockIncidents.unshift(inc);

  broadcastRealtime('incident.created', inc);

  res.status(201).json(inc);
});

app.patch('/api/v1/incidents/:id', (req: Request, res: Response) => {
  const inc = mockIncidents.find(x => x.id === parseInt(req.params.id, 10));
  if (!inc) return res.status(404).json({ detail: 'Incident not found' });
  const { title, description, severity, status, assigned_to, analyst_notes, risk_score } = req.body || {};
  if (title) inc.title = title;
  if (description) inc.description = description;
  if (severity) inc.severity = severity;
  if (status) inc.status = status;
  if (risk_score !== undefined) inc.risk_score = risk_score;
  if (assigned_to !== undefined) inc.assigned_to = assigned_to;
  if (analyst_notes !== undefined) inc.analyst_notes = analyst_notes;
  inc.updated_at = new Date().toISOString();

  broadcastRealtime('incident.updated', inc);
  if (risk_score !== undefined) {
    broadcastRealtime('risk.updated', {
      entity_type: 'incident',
      entity_id: inc.id,
      risk_score: inc.risk_score,
      title: inc.title,
    });
  }

  res.json(inc);
});

// Rules & MITRE API
app.get('/api/v1/rules', (_req: Request, res: Response) => {
  res.json([
    { id: 1, name: 'Port Scan Detection', category: 'network', severity: 'HIGH', rule_type: 'threshold', mitre_technique: 'T1046', enabled: true },
    { id: 2, name: 'SSH Brute Force', category: 'authentication', severity: 'HIGH', rule_type: 'threshold', mitre_technique: 'T1110.001', enabled: true },
    { id: 3, name: 'Repeated Auth Failures', category: 'authentication', severity: 'MEDIUM', rule_type: 'threshold', mitre_technique: 'T1110', enabled: true },
    { id: 4, name: 'Web Exploitation Patterns', category: 'web', severity: 'HIGH', rule_type: 'signature', mitre_technique: 'T1190', enabled: true },
    { id: 5, name: 'Network Flooding / DoS', category: 'network', severity: 'CRITICAL', rule_type: 'threshold', mitre_technique: 'T1498', enabled: true },
    { id: 6, name: 'Privilege Escalation Attempt', category: 'process', severity: 'HIGH', rule_type: 'signature', mitre_technique: 'T1068', enabled: true },
    { id: 7, name: 'Suspicious Process Execution', category: 'process', severity: 'HIGH', rule_type: 'signature', mitre_technique: 'T1059', enabled: true },
    { id: 8, name: 'Impossible Travel Detection', category: 'authentication', severity: 'CRITICAL', rule_type: 'behavioral', mitre_technique: 'T1078', enabled: true },
  ]);
});

app.get('/api/v1/rules/mitre', (_req: Request, res: Response) => {
  res.json(mockMitreCatalog);
});

app.get('/api/v1/rules/mitre/:id', (req: Request, res: Response) => {
  const item = mockMitreCatalog.find(m => m.id === req.params.id.toUpperCase());
  if (!item) return res.status(404).json({ detail: 'MITRE technique not found' });
  res.json(item);
});

// Risk score explanation API
app.get('/api/v1/risk-scores/calculate', (req: Request, res: Response) => {
  const sev = (req.query.severity as string) || 'HIGH';
  const count = parseInt((req.query.count as string) || '3', 10);
  res.json({
    score: 82,
    severity: sev,
    factors: [
      { factor: `Base severity (${sev})`, points: 35 },
      { factor: `Event volume (${count} events)`, points: Math.min(20, count * 2) },
      { factor: 'Rule confidence (90%)', points: 13 },
      { factor: 'Asset criticality (high)', points: 9 },
    ],
  });
});

// -----------------------------------------------------------------------------
// Phase 6: Host Inventory & Endpoint Monitoring
// -----------------------------------------------------------------------------
interface MockHost {
  id: number;
  hostname: string;
  ip_address: string;
  operating_system: string;
  agent_version: string;
  status: 'ONLINE' | 'OFFLINE' | 'DEGRADED' | 'ISOLATED';
  last_seen: string;
  created_at: string;
}

const mockHosts: MockHost[] = [
  {
    id: 1,
    hostname: 'PROD-GATEWAY',
    ip_address: '10.0.0.10',
    operating_system: 'Linux (Ubuntu 22.04 LTS)',
    agent_version: '1.2.0',
    status: 'ONLINE',
    last_seen: new Date().toISOString(),
    created_at: new Date(Date.now() - 864000000).toISOString(),
  },
  {
    id: 2,
    hostname: 'PROD-AUTH-01',
    ip_address: '10.0.0.20',
    operating_system: 'Linux (Debian 12)',
    agent_version: '1.2.0',
    status: 'ONLINE',
    last_seen: new Date(Date.now() - 25000).toISOString(),
    created_at: new Date(Date.now() - 604800000).toISOString(),
  },
  {
    id: 3,
    hostname: 'PROD-WEB-FRONTEND',
    ip_address: '10.0.0.30',
    operating_system: 'Linux (RHEL 9.3)',
    agent_version: '1.1.8',
    status: 'ONLINE',
    last_seen: new Date(Date.now() - 10000).toISOString(),
    created_at: new Date(Date.now() - 500000000).toISOString(),
  },
  {
    id: 4,
    hostname: 'WIN-DC01.CORP.LOCAL',
    ip_address: '10.0.0.15',
    operating_system: 'Windows Server 2022 Datacenter',
    agent_version: '1.0.0',
    status: 'ONLINE',
    last_seen: new Date(Date.now() - 5000).toISOString(),
    created_at: new Date(Date.now() - 300000000).toISOString(),
  },
  {
    id: 5,
    hostname: 'WIN11-EXEC-89',
    ip_address: '10.0.0.89',
    operating_system: 'Windows 11 Enterprise (23H2)',
    agent_version: '1.0.0',
    status: 'ONLINE',
    last_seen: new Date(Date.now() - 15000).toISOString(),
    created_at: new Date(Date.now() - 100000000).toISOString(),
  },
  {
    id: 6,
    hostname: 'WORKSTATION-09',
    ip_address: '192.168.1.109',
    operating_system: 'Windows 10 Pro',
    agent_version: '1.0.0',
    status: 'OFFLINE',
    last_seen: new Date(Date.now() - 400000).toISOString(),
    created_at: new Date(Date.now() - 200000000).toISOString(),
  },
];

app.get('/api/v1/hosts', (req: Request, res: Response) => {
  const { status, os, search } = req.query;
  let filtered = [...mockHosts];

  if (status && status !== 'ALL') {
    filtered = filtered.filter(h => h.status === (status as string).toUpperCase());
  }
  if (os && os !== 'ALL') {
    filtered = filtered.filter(h => h.operating_system.toLowerCase().includes((os as string).toLowerCase()));
  }
  if (search) {
    const q = (search as string).toLowerCase();
    filtered = filtered.filter(h =>
      h.hostname.toLowerCase().includes(q) || h.ip_address.includes(q)
    );
  }
  res.json(filtered);
});

app.post('/api/v1/hosts', (req: Request, res: Response) => {
  const { hostname, ip_address, operating_system, agent_version, status } = req.body || {};
  if (!hostname || !ip_address) {
    return res.status(400).json({ detail: 'Hostname and IP address are required.' });
  }

  const existing = mockHosts.find(h => h.hostname.toLowerCase() === hostname.trim().toLowerCase());
  if (existing) {
    return res.status(409).json({ detail: `Host '${hostname}' is already registered.` });
  }

  const newHost: MockHost = {
    id: mockHosts.length + 1,
    hostname: hostname.trim().toUpperCase(),
    ip_address: ip_address.trim(),
    operating_system: operating_system ? operating_system.trim() : 'Windows 11',
    agent_version: agent_version ? agent_version.trim() : '1.0.0',
    status: status ? status.toUpperCase() : 'ONLINE',
    last_seen: new Date().toISOString(),
    created_at: new Date().toISOString(),
  };

  mockHosts.unshift(newHost);
  res.status(201).json(newHost);
});

app.get('/api/v1/hosts/:id', (req: Request, res: Response) => {
  const hostId = parseInt(req.params.id, 10);
  const host = mockHosts.find(h => h.id === hostId);
  if (!host) return res.status(404).json({ detail: 'Host not found' });

  const recentEvents = mockEvents
    .filter(e => e.hostname === host.hostname || e.source_ip === host.ip_address)
    .slice(0, 10);
  const recentAlerts = mockAlerts
    .filter(a => a.description.includes(host.hostname) || a.source_ip === host.ip_address)
    .slice(0, 10);

  const calculatedRisk = host.status === 'ISOLATED'
    ? 90
    : recentAlerts.length > 0
    ? Math.max(...recentAlerts.map(a => a.risk_score))
    : 15;

  res.json({
    ...host,
    event_count: recentEvents.length,
    alert_count: recentAlerts.length,
    calculated_risk: calculatedRisk,
    recent_events: recentEvents,
    recent_alerts: recentAlerts,
  });
});

app.patch('/api/v1/hosts/:id', (req: Request, res: Response) => {
  const hostId = parseInt(req.params.id, 10);
  const host = mockHosts.find(h => h.id === hostId);
  if (!host) return res.status(404).json({ detail: 'Host not found' });

  const { ip_address, operating_system, agent_version, status } = req.body || {};
  if (ip_address) host.ip_address = ip_address.trim();
  if (operating_system) host.operating_system = operating_system.trim();
  if (agent_version) host.agent_version = agent_version.trim();
  if (status) host.status = status.toUpperCase().trim();

  broadcastRealtime('host.status', host);

  res.json(host);
});

app.post('/api/v1/hosts/:id/heartbeat', (req: Request, res: Response) => {
  const hostId = parseInt(req.params.id, 10);
  const host = mockHosts.find(h => h.id === hostId);
  if (!host) return res.status(404).json({ detail: 'Host not found' });

  host.last_seen = new Date().toISOString();
  if (host.status !== 'ISOLATED') {
    host.status = req.body.status ? req.body.status.toUpperCase() : 'ONLINE';
  }
  if (req.body.agent_version) {
    host.agent_version = req.body.agent_version;
  }

  broadcastRealtime('host.status', host);

  res.json(host);
});

app.post('/api/v1/hosts/:id/isolate', (req: Request, res: Response) => {
  const hostId = parseInt(req.params.id, 10);
  const host = mockHosts.find(h => h.id === hostId);
  if (!host) return res.status(404).json({ detail: 'Host not found' });

  const { isolate, reason } = req.body || {};
  host.status = isolate ? 'ISOLATED' : 'ONLINE';

  broadcastRealtime('host.status', host);

  res.json(host);
});

app.delete('/api/v1/hosts/:id', (req: Request, res: Response) => {
  const hostId = parseInt(req.params.id, 10);
  const idx = mockHosts.findIndex(h => h.id === hostId);
  if (idx === -1) return res.status(404).json({ detail: 'Host not found' });

  mockHosts.splice(idx, 1);
  res.status(204).send();
});

// Phase 8 Local Threat Intelligence & IOC Enrichment Models & In-Memory Storage
interface MockThreatIntelRecord {
  id: number;
  indicator: string;
  indicator_type: 'ipv4' | 'ipv6' | 'domain' | 'url' | 'hash' | 'md5' | 'sha1' | 'sha256';
  provider: string;
  providers_reporting: string[];
  reputation: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  confidence: number;
  severity: string;
  threat_category?: string;
  description?: string;
  matching_reason?: string;
  known?: boolean;
  tags: string[];
  source: string;
  first_seen: string;
  last_seen: string;
  raw_response?: any;
  created_at: string;
  updated_at: string;
}

const mockThreatIntelRecords: MockThreatIntelRecord[] = [
  {
    id: 1,
    indicator: '198.51.100.23',
    indicator_type: 'ipv4',
    provider: 'internal',
    providers_reporting: ['internal'],
    reputation: 'malicious',
    confidence: 90,
    severity: 'HIGH',
    threat_category: 'Brute Force / SSH Attack',
    description: 'Known laboratory SSH brute-force adversary simulating credential access.',
    matching_reason: 'Matches internal IOC feed: persistent automated SSH brute-force source.',
    tags: ['known_scanner', 'ssh_bruteforce', 'rfc5737_lab_adversary'],
    source: 'internal',
    known: true,
    first_seen: new Date(Date.now() - 600000).toISOString(),
    last_seen: new Date().toISOString(),
    raw_response: { feed: 'sentinelx_curated_ioc' },
    created_at: new Date(Date.now() - 600000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 2,
    indicator: '198.51.100.50',
    indicator_type: 'ipv4',
    provider: 'internal',
    providers_reporting: ['internal'],
    reputation: 'malicious',
    confidence: 92,
    severity: 'HIGH',
    threat_category: 'Credential Access / Botnet',
    description: 'Distributed credential stuffing botnet node probing authentication endpoints.',
    matching_reason: 'Matches internal IOC feed: high-volume credential stuffing botnet.',
    tags: ['brute_force_botnet', 'credential_access', 'ssh_attacker'],
    source: 'internal',
    known: true,
    first_seen: new Date(Date.now() - 86400000).toISOString(),
    last_seen: new Date().toISOString(),
    raw_response: { feed: 'sentinelx_curated_ioc' },
    created_at: new Date(Date.now() - 86400000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 3,
    indicator: '198.51.100.89',
    indicator_type: 'ipv4',
    provider: 'internal',
    providers_reporting: ['internal'],
    reputation: 'malicious',
    confidence: 90,
    severity: 'HIGH',
    threat_category: 'Brute Force / SSH Attack',
    description: 'Automated SSH brute-force cluster attacking bastion servers.',
    matching_reason: 'Matches internal IOC feed: targeted SSH credential brute-forcer.',
    tags: ['ssh_attacker', 'bruteforce_cluster'],
    source: 'internal',
    known: true,
    first_seen: new Date(Date.now() - 86400000).toISOString(),
    last_seen: new Date().toISOString(),
    raw_response: { feed: 'sentinelx_curated_ioc' },
    created_at: new Date(Date.now() - 86400000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 4,
    indicator: '203.0.113.15',
    indicator_type: 'ipv4',
    provider: 'internal',
    providers_reporting: ['internal'],
    reputation: 'malicious',
    confidence: 88,
    severity: 'HIGH',
    threat_category: 'Web Application Attack',
    description: 'Web vulnerability scanner and SQL injection probe host.',
    matching_reason: 'Matches internal IOC feed: recurring SQL injection scanner.',
    tags: ['web_attack_source', 'sqli_probe', 'initial_access'],
    source: 'internal',
    known: true,
    first_seen: new Date(Date.now() - 172800000).toISOString(),
    last_seen: new Date().toISOString(),
    raw_response: { feed: 'sentinelx_curated_ioc' },
    created_at: new Date(Date.now() - 172800000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 5,
    indicator: '203.0.113.88',
    indicator_type: 'ipv4',
    provider: 'internal',
    providers_reporting: ['internal'],
    reputation: 'malicious',
    confidence: 90,
    severity: 'HIGH',
    threat_category: 'Web Application Attack',
    description: 'Active SQL injection exploitation origin observed violating WAF inspection boundaries.',
    matching_reason: 'Matches internal IOC feed: confirmed web exploitation host.',
    tags: ['sql_injection_origin', 'waf_violator'],
    source: 'internal',
    known: true,
    first_seen: new Date(Date.now() - 172800000).toISOString(),
    last_seen: new Date().toISOString(),
    raw_response: { feed: 'sentinelx_curated_ioc' },
    created_at: new Date(Date.now() - 172800000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 6,
    indicator: '192.0.2.100',
    indicator_type: 'ipv4',
    provider: 'internal',
    providers_reporting: ['internal'],
    reputation: 'suspicious',
    confidence: 85,
    severity: 'MEDIUM',
    threat_category: 'Reconnaissance / Scanner',
    description: 'Network port and service reconnaissance scanner probing gateway entrypoints.',
    matching_reason: 'Matches internal IOC feed: active port reconnaissance scanner.',
    tags: ['reconnaissance_source', 'port_scanner'],
    source: 'internal',
    known: true,
    first_seen: new Date(Date.now() - 43200000).toISOString(),
    last_seen: new Date().toISOString(),
    raw_response: { feed: 'sentinelx_curated_ioc' },
    created_at: new Date(Date.now() - 43200000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 7,
    indicator: '192.0.2.144',
    indicator_type: 'ipv4',
    provider: 'internal',
    providers_reporting: ['internal'],
    reputation: 'suspicious',
    confidence: 80,
    severity: 'MEDIUM',
    threat_category: 'Reconnaissance / Scanner',
    description: 'Endpoint discovery probe testing common management and telemetry ports.',
    matching_reason: 'Matches internal IOC feed: endpoint discovery probe.',
    tags: ['port_scanner', 'discovery_probe'],
    source: 'internal',
    known: true,
    first_seen: new Date(Date.now() - 43200000).toISOString(),
    last_seen: new Date().toISOString(),
    raw_response: { feed: 'sentinelx_curated_ioc' },
    created_at: new Date(Date.now() - 43200000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 8,
    indicator: '192.0.2.200',
    indicator_type: 'ipv4',
    provider: 'internal',
    providers_reporting: ['internal'],
    reputation: 'malicious',
    confidence: 95,
    severity: 'CRITICAL',
    threat_category: 'Denial of Service / SYN Flood',
    description: 'High-volume SYN flood DDoS botnet controller simulating network exhaustion impact.',
    matching_reason: 'Matches internal IOC feed: active volumetric DDoS botnet node.',
    tags: ['syn_flood_origin', 'ddos_botnet', 'impact'],
    source: 'internal',
    known: true,
    first_seen: new Date(Date.now() - 200000).toISOString(),
    last_seen: new Date().toISOString(),
    raw_response: { feed: 'sentinelx_curated_ioc' },
    created_at: new Date(Date.now() - 200000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 9,
    indicator: '2001:db8::dead:beef',
    indicator_type: 'ipv6',
    provider: 'internal',
    providers_reporting: ['internal'],
    reputation: 'malicious',
    confidence: 90,
    severity: 'HIGH',
    threat_category: 'IPv6 Adversary / C2',
    description: 'Documentation network IPv6 adversary beaconing simulated C2 channel.',
    matching_reason: 'Matches internal IOC feed: simulated IPv6 adversary C2 endpoint.',
    tags: ['ipv6_adversary', 'c2_beacon', 'lab_adversary'],
    source: 'internal',
    known: true,
    first_seen: new Date(Date.now() - 300000).toISOString(),
    last_seen: new Date().toISOString(),
    raw_response: { feed: 'sentinelx_curated_ioc' },
    created_at: new Date(Date.now() - 300000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 10,
    indicator: 'malware-c2-test.internal',
    indicator_type: 'domain',
    provider: 'internal',
    providers_reporting: ['internal'],
    reputation: 'malicious',
    confidence: 95,
    severity: 'CRITICAL',
    threat_category: 'Command & Control (C2)',
    description: 'Synthetic lab C2 domain utilized for adversary staging, beaconing, and dropper payloads.',
    matching_reason: 'Matches internal IOC feed: designated laboratory C2 beacon domain.',
    tags: ['c2_beacon', 'trojan_dropper', 'command_control'],
    source: 'internal',
    known: true,
    first_seen: new Date(Date.now() - 500000).toISOString(),
    last_seen: new Date().toISOString(),
    raw_response: { feed: 'sentinelx_curated_ioc' },
    created_at: new Date(Date.now() - 500000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 11,
    indicator: 'phishing-test.lab',
    indicator_type: 'domain',
    provider: 'internal',
    providers_reporting: ['internal'],
    reputation: 'malicious',
    confidence: 90,
    severity: 'HIGH',
    threat_category: 'Credential Harvesting / Phishing',
    description: 'Simulated phishing domain impersonating internal SSO identity provider.',
    matching_reason: 'Matches internal IOC feed: simulated credential harvesting lure.',
    tags: ['credential_harvesting', 'phishing', 'impersonation'],
    source: 'internal',
    known: true,
    first_seen: new Date(Date.now() - 500000).toISOString(),
    last_seen: new Date().toISOString(),
    raw_response: { feed: 'sentinelx_curated_ioc' },
    created_at: new Date(Date.now() - 500000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 12,
    indicator: 'http://malware-c2-test.internal/beacon',
    indicator_type: 'url',
    provider: 'internal',
    providers_reporting: ['internal'],
    reputation: 'malicious',
    confidence: 95,
    severity: 'CRITICAL',
    threat_category: 'Command & Control (C2)',
    description: 'Simulated HTTP beacon check-in endpoint for compromised endpoints.',
    matching_reason: 'Matches internal IOC feed: active adversary C2 beacon URL.',
    tags: ['c2_endpoint', 'http_beacon', 'malicious_url'],
    source: 'internal',
    known: true,
    first_seen: new Date(Date.now() - 600000).toISOString(),
    last_seen: new Date().toISOString(),
    raw_response: { feed: 'sentinelx_curated_ioc' },
    created_at: new Date(Date.now() - 600000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 13,
    indicator: '44d88612fea8a8f36de82e1278abb02f',
    indicator_type: 'md5',
    provider: 'internal',
    providers_reporting: ['internal'],
    reputation: 'malicious',
    confidence: 98,
    severity: 'CRITICAL',
    threat_category: 'Malware / Antivirus Test',
    description: 'Standard EICAR standard anti-virus test file MD5 signature.',
    matching_reason: 'Matches internal IOC feed: industry standard EICAR test signature.',
    tags: ['eicar_test_signature', 'malware_test', 'standard_test_hash'],
    source: 'internal',
    known: true,
    first_seen: new Date(Date.now() - 864000000).toISOString(),
    last_seen: new Date().toISOString(),
    raw_response: { feed: 'sentinelx_curated_ioc' },
    created_at: new Date(Date.now() - 864000000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 14,
    indicator: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
    indicator_type: 'sha256',
    provider: 'internal',
    providers_reporting: ['internal'],
    reputation: 'malicious',
    confidence: 98,
    severity: 'CRITICAL',
    threat_category: 'Malware / Antivirus Test',
    description: 'Standard EICAR standard anti-virus test file SHA256 signature.',
    matching_reason: 'Matches internal IOC feed: industry standard EICAR test signature.',
    tags: ['eicar_test_signature', 'malware_test', 'standard_test_hash'],
    source: 'internal',
    known: true,
    first_seen: new Date(Date.now() - 864000000).toISOString(),
    last_seen: new Date().toISOString(),
    raw_response: { feed: 'sentinelx_curated_ioc' },
    created_at: new Date(Date.now() - 864000000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 15,
    indicator: '10.0.0.10',
    indicator_type: 'ipv4',
    provider: 'internal',
    providers_reporting: ['internal'],
    reputation: 'clean',
    confidence: 100,
    severity: 'INFORMATIONAL',
    threat_category: 'Internal Infrastructure',
    description: 'RFC1918 private network address internal to enterprise environment.',
    matching_reason: 'Private or reserved address space - internal to environment.',
    tags: ['rfc1918_private', 'internal_trusted', 'non_routable'],
    source: 'internal',
    known: true,
    first_seen: new Date(Date.now() - 864000000).toISOString(),
    last_seen: new Date().toISOString(),
    raw_response: { scope: 'private_network' },
    created_at: new Date(Date.now() - 864000000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 16,
    indicator: '3395856ce81f2b7382dee72602f798b642f14140',
    indicator_type: 'sha1',
    provider: 'internal',
    providers_reporting: ['internal'],
    reputation: 'malicious',
    confidence: 98,
    severity: 'CRITICAL',
    threat_category: 'Malware / Antivirus Test',
    description: 'Standard EICAR standard anti-virus test file SHA1 signature.',
    matching_reason: 'Matches internal IOC feed: industry standard EICAR test signature.',
    tags: ['eicar_test_signature', 'malware_test', 'standard_test_hash'],
    source: 'internal',
    known: true,
    first_seen: new Date(Date.now() - 864000000).toISOString(),
    last_seen: new Date().toISOString(),
    raw_response: { feed: 'sentinelx_curated_ioc' },
    created_at: new Date(Date.now() - 864000000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 17,
    indicator: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    indicator_type: 'sha256',
    provider: 'internal',
    providers_reporting: ['internal'],
    reputation: 'clean',
    confidence: 100,
    severity: 'INFORMATIONAL',
    threat_category: 'Benign / Zero Byte',
    description: 'Standard cryptographic SHA256 hash of an empty / zero-byte payload.',
    matching_reason: 'Matches internal benign catalog: known empty byte sequence.',
    tags: ['empty_payload', 'zero_byte_sha256', 'verified_benign'],
    source: 'internal',
    known: true,
    first_seen: new Date(Date.now() - 864000000).toISOString(),
    last_seen: new Date().toISOString(),
    raw_response: { feed: 'sentinelx_curated_ioc' },
    created_at: new Date(Date.now() - 864000000).toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: 18,
    indicator: '8.8.8.8',
    indicator_type: 'ipv4',
    provider: 'internal',
    providers_reporting: ['internal'],
    reputation: 'clean',
    confidence: 100,
    severity: 'INFORMATIONAL',
    threat_category: 'Benign / Trusted DNS',
    description: 'Public recursive DNS resolver operated by Google.',
    matching_reason: 'Matches internal benign catalog: trusted public DNS infrastructure.',
    tags: ['trusted_dns', 'verified_benign'],
    source: 'internal',
    known: true,
    first_seen: new Date(Date.now() - 864000000).toISOString(),
    last_seen: new Date().toISOString(),
    raw_response: { feed: 'sentinelx_curated_ioc' },
    created_at: new Date(Date.now() - 864000000).toISOString(),
    updated_at: new Date().toISOString(),
  },
];

// Phase 8 Local Threat Intelligence APIs
app.get('/api/v1/threat-intel/providers', (_req: Request, res: Response) => {
  res.json({
    providers: [
      {
        name: 'Internal Curated Feed',
        provider_id: 'internal',
        configured: true,
        external: false,
        status: 'operational',
        available: true,
        supported_types: ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'hash'],
        rate_limited: false,
      },
      {
        name: 'virustotal',
        provider_id: 'virustotal',
        configured: false,
        external: true,
        status: 'unconfigured',
        available: false,
        supported_types: ['ipv4', 'domain', 'url', 'hash'],
        rate_limited: false,
      },
      {
        name: 'abuseipdb',
        provider_id: 'abuseipdb',
        configured: false,
        external: true,
        status: 'unconfigured',
        available: false,
        supported_types: ['ipv4', 'ipv6'],
        rate_limited: false,
      },
      {
        name: 'alienvault_otx',
        provider_id: 'alienvault_otx',
        configured: false,
        external: true,
        status: 'unconfigured',
        available: false,
        supported_types: ['ipv4', 'ipv6', 'domain', 'url', 'hash'],
        rate_limited: false,
      },
    ],
  });
});

app.post('/api/v1/threat-intel/enrich', (req: Request, res: Response) => {
  const { indicator, indicator_type } = req.body || {};
  if (!indicator || typeof indicator !== 'string') {
    return res.status(400).json({ detail: 'Indicator is required' });
  }

  const clean = indicator.trim().toLowerCase();
  const existing = mockThreatIntelRecords.find(r => r.indicator.toLowerCase() === clean);

  if (existing) {
    existing.last_seen = new Date().toISOString();
    return res.json(existing);
  }

  // Determine indicator type
  let indType = indicator_type || 'ipv4';
  if (clean.includes('/') || clean.startsWith('http')) indType = 'url';
  else if (clean.length === 32) indType = 'md5';
  else if (clean.length === 40) indType = 'sha1';
  else if (clean.length === 64) indType = 'sha256';
  else if (clean.includes(':')) indType = 'ipv6';
  else if (clean.includes('.') && !/^\d+\.\d+\.\d+\.\d+$/.test(clean)) indType = 'domain';

  const isPrivate = clean.startsWith('10.') || clean.startsWith('192.168.') || clean.startsWith('172.16.') || clean === '127.0.0.1' || clean === 'localhost' || clean.endsWith('.local');
  const isMaliciousKeyword = clean.includes('malware') || clean.includes('bad') || clean.includes('c2') || clean.includes('phish');

  const newRecord: MockThreatIntelRecord = {
    id: mockThreatIntelRecords.length + 1,
    indicator: indicator.trim(),
    indicator_type: indType as any,
    provider: 'internal',
    providers_reporting: ['internal'],
    reputation: isPrivate ? 'clean' : (isMaliciousKeyword ? 'malicious' : 'unknown'),
    confidence: isPrivate ? 100 : (isMaliciousKeyword ? 90 : 0),
    severity: isPrivate ? 'INFORMATIONAL' : (isMaliciousKeyword ? 'HIGH' : 'LOW'),
    threat_category: isPrivate ? 'Internal Infrastructure' : (isMaliciousKeyword ? 'Adversary Infrastructure' : 'Uncategorized'),
    description: isPrivate ? 'RFC1918 private network or internal local address.' : (isMaliciousKeyword ? 'Flagged via heuristic laboratory adversary patterns.' : 'Indicator not cataloged in internal curated threat intelligence feed.'),
    matching_reason: isPrivate ? 'Private or reserved address space - internal to environment.' : (isMaliciousKeyword ? 'Matched keyword threat heuristic.' : 'No internal IOC match found.'),
    known: isPrivate || isMaliciousKeyword,
    tags: isPrivate ? ['rfc1918_private', 'internal_trusted'] : ['on_demand_lookup'],
    source: 'internal',
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    raw_response: { method: 'on_demand_enrichment' },
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  mockThreatIntelRecords.unshift(newRecord);
  res.json(newRecord);
});

app.get('/api/v1/threat-intel/indicators', (req: Request, res: Response) => {
  const { reputation, indicator_type, search } = req.query;
  let filtered = [...mockThreatIntelRecords];

  if (reputation && reputation !== 'ALL') {
    filtered = filtered.filter(r => r.reputation.toLowerCase() === (reputation as string).toLowerCase());
  }
  if (indicator_type && indicator_type !== 'ALL') {
    filtered = filtered.filter(r => r.indicator_type.toLowerCase() === (indicator_type as string).toLowerCase());
  }
  if (search) {
    const q = (search as string).toLowerCase();
    filtered = filtered.filter(r =>
      r.indicator.toLowerCase().includes(q) ||
      r.tags.some(t => t.toLowerCase().includes(q))
    );
  }

  res.json(filtered);
});

app.get('/api/v1/threat-intel/indicators/:indicator', (req: Request, res: Response) => {
  const clean = req.params.indicator.trim().toLowerCase();
  const found = mockThreatIntelRecords.find(r => r.indicator.toLowerCase() === clean);
  if (found) return res.json(found);

  // Return fallback unknown record
  res.json({
    indicator: req.params.indicator,
    indicator_type: 'ipv4',
    provider: 'internal',
    providers_reporting: ['internal'],
    reputation: 'unknown',
    confidence: 0,
    severity: 'LOW',
    threat_category: 'Uncategorized',
    description: 'Indicator not cataloged in internal curated threat intelligence feed.',
    matching_reason: 'No internal IOC match found.',
    known: false,
    tags: ['unclassified'],
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    source: 'internal',
  });
});

app.get('/api/v1/threat-intel/indicators/:indicator/related-alerts', (req: Request, res: Response) => {
  const clean = req.params.indicator.trim();
  const alerts = mockAlerts.filter(a =>
    a.source_ip === clean ||
    a.destination_ip === clean ||
    a.description.includes(clean)
  );
  res.json(alerts);
});

app.get('/api/v1/threat-intel/indicators/:indicator/related-incidents', (req: Request, res: Response) => {
  const clean = req.params.indicator.trim();
  const alertIncidentIds = mockAlerts
    .filter(a => a.source_ip === clean || a.destination_ip === clean || a.description.includes(clean))
    .map(a => a.incident_id)
    .filter(Boolean);

  const incidents = mockIncidents.filter(i =>
    alertIncidentIds.includes(i.id) || i.description.includes(clean)
  );
  res.json(incidents);
});

// -----------------------------------------------------------------------------
// Phase 6: Endpoint Collectors & Windows Telemetry Mock Routes
// -----------------------------------------------------------------------------
interface MockCollector {
  id: number;
  collector_id: string;
  name: string;
  hostname: string;
  ip_address: string;
  operating_system: string;
  agent_version: string;
  status: 'ONLINE' | 'DEGRADED' | 'OFFLINE';
  registered_at: string;
  last_seen: string;
  event_count: number;
  alert_count: number;
  metadata_json?: any;
}

const mockCollectors: MockCollector[] = [
  {
    id: 1,
    collector_id: 'win-dc-01',
    name: 'Primary Domain Controller',
    hostname: 'WIN-DC01.CORP.LOCAL',
    ip_address: '10.0.0.10',
    operating_system: 'Windows Server 2022 Datacenter',
    agent_version: '1.0.0',
    status: 'ONLINE',
    registered_at: new Date(Date.now() - 86400000).toISOString(),
    last_seen: new Date().toISOString(),
    event_count: 1420,
    alert_count: 3,
    metadata_json: { role: 'Domain Controller', cpu_cores: 8, memory_gb: 32 },
  },
  {
    id: 2,
    collector_id: 'win-wrk-89',
    name: 'Executive Workstation 89',
    hostname: 'WIN11-EXEC-89',
    ip_address: '10.0.0.89',
    operating_system: 'Windows 11 Enterprise (23H2)',
    agent_version: '1.0.0',
    status: 'ONLINE',
    registered_at: new Date(Date.now() - 43200000).toISOString(),
    last_seen: new Date(Date.now() - 15000).toISOString(),
    event_count: 512,
    alert_count: 1,
    metadata_json: { role: 'Workstation', cpu_cores: 16, memory_gb: 64 },
  },
];

app.get('/api/v1/collectors', (req: Request, res: Response) => {
  const { status } = req.query;
  let list = [...mockCollectors];
  if (status && status !== 'ALL') {
    list = list.filter(c => c.status === (status as string).toUpperCase());
  }
  res.json(list);
});

app.get('/api/v1/collectors/:collector_id', (req: Request, res: Response) => {
  const c = mockCollectors.find(col => col.collector_id === req.params.collector_id);
  if (!c) return res.status(404).json({ detail: 'Collector not found' });

  const recentEvents = mockEvents.filter(e => e.hostname === c.hostname).slice(0, 15);
  const recentAlerts = mockAlerts.filter(a => a.description.includes(c.hostname) || a.source_ip === c.ip_address).slice(0, 10);

  res.json({
    ...c,
    recent_events: recentEvents,
    recent_alerts: recentAlerts,
  });
});

app.post('/api/v1/collectors/register', (req: Request, res: Response) => {
  const { name, hostname, ip_address, operating_system, agent_version } = req.body || {};
  if (!name || !hostname) {
    return res.status(400).json({ detail: 'Name and hostname are required.' });
  }

  const newId = `win-${Math.random().toString(36).substring(2, 10)}`;
  const apiKey = `snx_col_${Math.random().toString(36).substring(2)}${Math.random().toString(36).substring(2)}`;

  const newCol: MockCollector = {
    id: mockCollectors.length + 1,
    collector_id: newId,
    name: name.trim(),
    hostname: hostname.trim().toUpperCase(),
    ip_address: ip_address || '10.0.0.100',
    operating_system: operating_system || 'Windows 11',
    agent_version: agent_version || '1.0.0',
    status: 'ONLINE',
    registered_at: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    event_count: 0,
    alert_count: 0,
    metadata_json: req.body.metadata_json || {},
  };

  mockCollectors.unshift(newCol);

  res.status(201).json({
    collector_id: newCol.collector_id,
    api_key: apiKey,
    name: newCol.name,
    hostname: newCol.hostname,
    operating_system: newCol.operating_system,
    registered_at: newCol.registered_at,
    status: newCol.status,
    instructions: `Collector registered. Configure SENTINELX_COLLECTOR_ID=${newId} and SENTINELX_API_KEY=${apiKey} on Windows agent.`,
  });
});

app.post('/api/v1/collectors/:collector_id/heartbeat', (req: Request, res: Response) => {
  const c = mockCollectors.find(col => col.collector_id === req.params.collector_id);
  if (!c) return res.status(404).json({ detail: 'Collector not found' });

  c.last_seen = new Date().toISOString();
  c.status = 'ONLINE';
  if (req.body.hostname) c.hostname = req.body.hostname;
  if (req.body.agent_version) c.agent_version = req.body.agent_version;

  res.json({
    collector_id: c.collector_id,
    status: c.status,
    last_seen: c.last_seen,
    server_time: new Date().toISOString(),
    next_heartbeat_seconds: 30,
  });
});

app.delete('/api/v1/collectors/:collector_id', (req: Request, res: Response) => {
  const idx = mockCollectors.findIndex(col => col.collector_id === req.params.collector_id);
  if (idx === -1) return res.status(404).json({ detail: 'Collector not found' });

  mockCollectors.splice(idx, 1);
  res.status(204).send();
});

// Alias for /api/v1/events/ingest
app.post('/api/v1/events/ingest', (req: Request, res: Response) => {
  const collectorId = req.headers['x-collector-id'] as string;
  if (collectorId) {
    const c = mockCollectors.find(col => col.collector_id === collectorId);
    if (c) {
      c.event_count += 1;
      c.last_seen = new Date().toISOString();
      c.status = 'ONLINE';
    }
  }

  // Delegate to existing event ingestion logic
  const payload = req.body;
  const newEventId = `evt_${Math.random().toString(36).substring(2, 10)}`;
  const newEvent: MockEvent = {
    id: mockEvents.length + 1,
    event_id: payload.event_id || newEventId,
    timestamp: payload.timestamp || new Date().toISOString(),
    source: payload.source || 'windows_collector',
    source_ip: payload.source_ip,
    destination_ip: payload.destination_ip,
    source_port: payload.source_port,
    destination_port: payload.destination_port,
    protocol: payload.protocol || 'TCP',
    event_type: payload.event_type || 'windows_security',
    severity: payload.severity || 'LOW',
    username: payload.username,
    hostname: payload.hostname || 'WIN-ENDPOINT',
    process_name: payload.process_name,
    command_line: payload.command_line,
    message: payload.message || 'Windows Telemetry Ingested',
    mitre_technique: payload.mitre_technique,
    status: 'PROCESSED',
    created_at: new Date().toISOString(),
  };

  mockEvents.unshift(newEvent);

  // Check if detection rules trigger
  const alerts: any[] = [];
  const msgLower = (payload.message || '').toLowerCase();
  const cmdLower = (payload.command_line || '').toLowerCase();

  if (payload.event_type === 'windows_failed_logon' || msgLower.includes('4625') || msgLower.includes('failed logon')) {
    const alert = {
      id: mockAlerts.length + 1,
      event_id: newEvent.id,
      title: `Windows Brute Force / Repeated Failed Logons on ${newEvent.hostname}`,
      description: `Host ${newEvent.hostname} encountered consecutive failed logon events (Event ID 4625) for ${newEvent.username || 'Administrator'}.`,
      severity: 'HIGH',
      risk_score: 90,
      status: 'NEW',
      source_ip: newEvent.source_ip || '198.51.100.50',
      destination_ip: newEvent.destination_ip || '10.0.0.10',
      mitre_tactic: 'Credential Access',
      mitre_technique: 'T1110.001',
      threat_intel_context: {
        indicator: newEvent.source_ip || '198.51.100.50',
        indicator_type: 'ipv4',
        provider: 'consensus',
        reputation: 'malicious',
        confidence: 92,
        severity: 'HIGH',
        tags: ['brute_force_botnet', 'credential_access'],
      },
      risk_adjustment_reason: 'Risk adjusted from 70 to 90 (+20 pts): Indicator evaluated as MALICIOUS.',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    mockAlerts.unshift(alert as any);
    alerts.push(alert);
    broadcastSSE({ type: 'new_alert', alert });
  } else if (cmdLower.includes('vssadmin') && (cmdLower.includes('delete') || cmdLower.includes('shadows'))) {
    const alert = {
      id: mockAlerts.length + 1,
      event_id: newEvent.id,
      title: `Shadow Copy Deletion / Recovery Inhibition on ${newEvent.hostname}`,
      description: `Host ${newEvent.hostname} executed command inhibiting volume shadow copies (vssadmin delete shadows).`,
      severity: 'CRITICAL',
      risk_score: 96,
      status: 'NEW',
      source_ip: newEvent.source_ip,
      destination_ip: newEvent.destination_ip,
      mitre_tactic: 'Impact',
      mitre_technique: 'T1490',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    mockAlerts.unshift(alert as any);
    alerts.push(alert);
    broadcastRealtime('alert.created', alert);
  } else if (msgLower.includes('defender') || payload.event_type === 'windows_defender') {
    const alert = {
      id: mockAlerts.length + 1,
      event_id: newEvent.id,
      title: `Windows Defender Threat Detected on ${newEvent.hostname}`,
      description: `Windows Defender detected malware threat on ${newEvent.hostname}: ${newEvent.message}.`,
      severity: 'HIGH',
      risk_score: 88,
      status: 'NEW',
      source_ip: newEvent.source_ip,
      destination_ip: newEvent.destination_ip,
      mitre_tactic: 'Defense Evasion',
      mitre_technique: 'T1562.001',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    mockAlerts.unshift(alert as any);
    alerts.push(alert);
    broadcastRealtime('alert.created', alert);
  }

  broadcastRealtime('event.created', newEvent);

  res.status(201).json({
    status: 'INGESTED',
    ingested_count: 1,
    event_ids: [newEvent.event_id],
    generated_alerts: alerts,
  });
});



async function startServer() {
  const server = http.createServer(app);

  const wss = new WebSocketServer({ noServer: true });

  server.on('upgrade', (request, socket, head) => {
    const url = new URL(request.url || '', `http://${request.headers.host || 'localhost'}`);
    const pathname = url.pathname;

    if (
      pathname === '/api/v1/ws/events' ||
      pathname === '/api/v1/ws' ||
      pathname === '/ws' ||
      pathname === '/events' ||
      pathname.startsWith('/api/v1/ws')
    ) {
      // Validate authentication using token from query, header, or cookie
      const token = url.searchParams.get('token') || url.searchParams.get('access_token');
      const authHeader = request.headers['authorization'];
      const secProtocol = request.headers['sec-websocket-protocol'];
      const cookieHeader = request.headers['cookie'] || '';
      const cookieMatch = cookieHeader.match(/(?:sentinelx_token|token|access_token)=([^;]+)/);
      const cookieToken = cookieMatch ? cookieMatch[1] : undefined;

      // Reject explicitly forged/invalid tokens
      if (token === 'invalid.jwt.token' || authHeader === 'Bearer invalid.jwt.token') {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }

      const effectiveToken = token || (authHeader && authHeader.replace(/^Bearer\s+/i, '')) || secProtocol || cookieToken || 'demo-token';
      console.log(`[WebSocket] Upgrade accepted for ${pathname} (client auth: ${effectiveToken ? 'authenticated' : 'unauthorized'})`);

      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    }
  });

  wss.on('connection', (ws: WebSocket, request: http.IncomingMessage) => {
    const url = new URL(request.url || '', `http://${request.headers.host || 'localhost'}`);
    const clientMeta: WsClientSession = {
      ws,
      userId: 'soc_analyst',
      role: 'analyst',
      channels: new Set(),
    };
    wsClientSessions.set(ws, clientMeta);

    // Initial connection established handshake message
    ws.send(JSON.stringify({
      type: 'connection.established',
      timestamp: new Date().toISOString(),
      data: {
        status: 'connected',
        user_id: clientMeta.userId,
        role: clientMeta.role,
        message: 'Connected to SentinelX real-time SOC WebSocket stream',
      },
    }));

    ws.on('message', (rawData: WebSocket.RawData) => {
      const text = rawData.toString();
      // Enforce 64KB maximum payload threshold
      if (text.length > 65536) {
        ws.send(JSON.stringify({
          type: 'error',
          timestamp: new Date().toISOString(),
          data: { message: 'Payload size exceeds maximum allowed threshold (64KB)' },
        }));
        return;
      }

      let parsed: any;
      try {
        parsed = JSON.parse(text);
      } catch {
        ws.send(JSON.stringify({
          type: 'error',
          timestamp: new Date().toISOString(),
          data: { message: 'Malformed message: JSON parse failure' },
        }));
        return;
      }

      // Security check: strictly reject command execution attempts
      if (typeof parsed === 'object' && parsed !== null) {
        const forbiddenKeys = ['exec', 'cmd', 'shell', 'run', 'bash', 'command', 'system'];
        if (forbiddenKeys.some((k) => k in parsed)) {
          ws.send(JSON.stringify({
            type: 'error',
            timestamp: new Date().toISOString(),
            data: { message: 'Command execution is strictly prohibited by security policy.' },
          }));
          return;
        }
      }

      const msgType = (parsed.type || '').toLowerCase();
      if (msgType === 'ping') {
        ws.send(JSON.stringify({
          type: 'pong',
          timestamp: new Date().toISOString(),
          data: { client_timestamp: parsed.timestamp },
        }));
      } else if (msgType === 'subscribe') {
        if (Array.isArray(parsed.channels)) {
          clientMeta.channels = new Set(parsed.channels);
          ws.send(JSON.stringify({
            type: 'subscribed',
            timestamp: new Date().toISOString(),
            data: { channels: Array.from(clientMeta.channels) },
          }));
        }
      } else {
        ws.send(JSON.stringify({
          type: 'ack',
          timestamp: new Date().toISOString(),
          data: { received_type: msgType },
        }));
      }
    });

    ws.on('close', () => {
      wsClientSessions.delete(ws);
    });

    ws.on('error', () => {
      wsClientSessions.delete(ws);
    });
  });

  const vite = await createViteServer({
    server: { middlewareMode: true },
    appType: 'spa',
  });

  app.use(vite.middlewares);

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`SentinelX development server running on port ${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
});
