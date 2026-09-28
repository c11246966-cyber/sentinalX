import express, { Request, Response } from 'express';
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

// Threat intelligence proxy / fallback endpoint
app.get('/api/v1/threat-intel/:indicator', (req: Request, res: Response) => {
  const indicator = req.params.indicator;
  const isPrivate = indicator.startsWith('10.') || indicator.startsWith('192.168.') || indicator.startsWith('127.0.0.1');
  res.json({
    indicator,
    indicator_type: 'ip',
    reputation: isPrivate ? 'clean' : 'unknown',
    confidence: isPrivate ? 100 : 0,
    active_providers: ['internal'],
    external_lookups_enabled: false,
    status: isPrivate ? 'enriched' : 'no_external_match',
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
  created_at: string;
  updated_at: string;
}

const mockAlerts: MockAlert[] = [
  {
    id: 1,
    event_id: 1,
    title: 'Port Scanning Activity Detected from 192.0.2.100',
    description: 'Source 192.0.2.100 probed multiple ports across infrastructure within short window.',
    severity: 'HIGH',
    risk_score: 85,
    status: 'NEW',
    source_ip: '192.0.2.100',
    destination_ip: '10.0.0.10',
    mitre_tactic: 'Discovery',
    mitre_technique: 'T1046',
    created_at: new Date(Date.now() - 300000).toISOString(),
    updated_at: new Date(Date.now() - 300000).toISOString(),
  },
  {
    id: 2,
    event_id: 2,
    title: 'SSH Brute Force Attack from 198.51.100.50',
    description: 'Consecutive SSH authentication failures detected targeting root.',
    severity: 'HIGH',
    risk_score: 90,
    status: 'INVESTIGATING',
    source_ip: '198.51.100.50',
    destination_ip: '10.0.0.20',
    mitre_tactic: 'Credential Access',
    mitre_technique: 'T1110.001',
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

// Server-Sent Events subscribers
const sseClients = new Set<Response>();

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

  // Broadcast event real-time
  broadcastSSE({
    type: 'new_event',
    event: newEvt,
  });

  // Check if synthetic alert triggers
  const generatedAlerts: any[] = [];
  if (newEvt.event_type === 'port_scan' || newEvt.destination_port === 22 || newEvt.event_type.includes('fail') || newEvt.event_type.includes('flood')) {
    const alert: MockAlert = {
      id: mockAlerts.length + 1,
      event_id: newEvt.id,
      title: `Detection Triggered: ${newEvt.event_type} from ${newEvt.source_ip || 'host'}`,
      description: newEvt.message,
      severity: newEvt.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
      risk_score: newEvt.severity === 'CRITICAL' ? 95 : 85,
      status: 'NEW',
      source_ip: newEvt.source_ip,
      destination_ip: newEvt.destination_ip,
      mitre_technique: newEvt.mitre_technique || 'T1046',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    mockAlerts.unshift(alert);
    generatedAlerts.push(alert);

    // Broadcast alert real-time
    broadcastSSE({
      type: 'new_alert',
      alert,
    });
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

  broadcastSSE({
    type: 'alert_updated',
    alert: a,
  });

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

  broadcastSSE({
    type: 'new_incident',
    incident: inc,
  });

  res.status(201).json(inc);
});

app.patch('/api/v1/incidents/:id', (req: Request, res: Response) => {
  const inc = mockIncidents.find(x => x.id === parseInt(req.params.id, 10));
  if (!inc) return res.status(404).json({ detail: 'Incident not found' });
  const { title, description, severity, status, assigned_to, analyst_notes } = req.body || {};
  if (title) inc.title = title;
  if (description) inc.description = description;
  if (severity) inc.severity = severity;
  if (status) inc.status = status;
  if (assigned_to !== undefined) inc.assigned_to = assigned_to;
  if (analyst_notes !== undefined) inc.analyst_notes = analyst_notes;
  inc.updated_at = new Date().toISOString();

  broadcastSSE({
    type: 'incident_updated',
    incident: inc,
  });

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


async function startServer() {
  const vite = await createViteServer({
    server: { middlewareMode: true },
    appType: 'spa',
  });

  app.use(vite.middlewares);

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SentinelX development server running on port ${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
});
