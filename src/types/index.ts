export type ServiceStatus = 'healthy' | 'degraded' | 'unhealthy' | 'offline' | 'simulated';

export interface ServiceHealthDetail {
  status: ServiceStatus;
  latency_ms?: number;
  message?: string;
  version?: string;
}

export interface HealthCheckResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  version: string;
  environment: string;
  timestamp: string;
  services: Record<string, ServiceHealthDetail>;
}

export interface PipelineStage {
  id: string;
  step: number;
  title: string;
  category: string;
  description: string;
  phase: number;
  status: 'active' | 'in_development' | 'planned';
  mitreRef?: string;
}

export interface SystemMetric {
  label: string;
  value: string | number;
  change?: string;
  trend?: 'up' | 'down' | 'stable';
  status: 'normal' | 'warning' | 'critical' | 'neutral';
  icon: string;
}

export type AlertSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
export type AlertStatus = 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE' | 'TRIAGED';
export type IncidentStatus = 'NEW' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';
export type IndicatorReputation = 'clean' | 'suspicious' | 'malicious' | 'unknown';
export type IndicatorType = 'ipv4' | 'ipv6' | 'domain' | 'url' | 'hash';

export interface MitreTechnique {
  id: string;
  technique: string;
  tactic: string;
  description?: string;
  url: string;
  detections?: number;
  is_active?: boolean;
}

export interface SecurityEvent {
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
  severity: AlertSeverity;
  username?: string;
  hostname?: string;
  process_name?: string;
  command_line?: string;
  message: string;
  raw_event?: any;
  normalized_event?: any;
  mitre_technique?: string;
  status: string;
  created_at: string;
}

export interface ThreatIntelIndicator {
  id?: number;
  indicator: string;
  indicator_type: IndicatorType | string;
  provider: string;
  providers_reporting?: string[];
  reputation: IndicatorReputation;
  confidence: number;
  severity: AlertSeverity | string;
  tags: string[];
  source?: string;
  first_seen?: string;
  last_seen?: string;
  raw_response?: any;
  raw_provider_metadata?: any;
  created_at?: string;
  updated_at?: string;
}

export interface ThreatIntelProvider {
  name: string;
  configured: boolean;
  available: boolean;
  supported_types: string[];
  rate_limited?: boolean;
}

export interface Alert {
  id: number;
  event_id?: number;
  incident_id?: number;
  title: string;
  description: string;
  severity: AlertSeverity;
  risk_score: number;
  status: AlertStatus;
  source_ip?: string;
  destination_ip?: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  mitre_details?: MitreTechnique;
  analyst_notes?: string;
  threat_intel_context?: ThreatIntelIndicator | any;
  risk_adjustment_reason?: string;
  created_at: string;
  updated_at: string;
  event?: SecurityEvent;
}

export interface Incident {
  id: number;
  title: string;
  description: string;
  severity: AlertSeverity;
  risk_score: number;
  status: IncidentStatus;
  assigned_to?: number;
  assignee_name?: string;
  analyst_notes?: string;
  alert_count?: number;
  created_at: string;
  updated_at: string;
  resolved_at?: string;
  alerts?: Alert[];
  events?: SecurityEvent[];
}

export interface DetectionRule {
  id: number;
  name: string;
  category: string;
  severity: AlertSeverity;
  rule_type: string;
  mitre_technique?: string;
  enabled: boolean;
}

export interface ExecutiveOverview {
  defense_status: 'DEFENDING' | 'ELEVATED' | 'CRITICAL ALERT';
  total_events: number;
  total_alerts: number;
  active_alerts: number;
  open_incidents: number;
  critical_alerts: number;
  average_risk_score: number;
  tactics_covered: number;
  total_rules: number;
}

export interface DashboardStats {
  executive_overview: ExecutiveOverview;
  severity_counts: Record<AlertSeverity, number>;
  risk_distribution: Record<string, number>;
  event_timeline: Array<{
    time: string;
    events: number;
    alerts: number;
  }>;
  top_source_ips: Array<{ ip: string; event_count: number }>;
  top_affected_assets: Array<{ asset: string; event_count: number }>;
  mitre_coverage: MitreTechnique[];
  recent_alerts: Alert[];
  recent_incidents: Incident[];
}

export type RealtimeStatus = 'connected' | 'reconnecting' | 'disconnected';

export type CollectorStatus = 'ONLINE' | 'DEGRADED' | 'OFFLINE';

export interface Collector {
  id: number;
  collector_id: string;
  name: string;
  hostname: string;
  ip_address: string;
  operating_system: string;
  agent_version: string;
  status: CollectorStatus;
  registered_at: string;
  last_seen: string;
  event_count: number;
  alert_count: number;
  metadata_json?: any;
  recent_events?: SecurityEvent[];
  recent_alerts?: Alert[];
}

export interface CollectorRegisterPayload {
  name: string;
  hostname: string;
  ip_address: string;
  operating_system?: string;
  agent_version?: string;
  metadata_json?: any;
}

export interface CollectorRegisterResponse {
  collector_id: string;
  api_key: string;
  name: string;
  hostname: string;
  operating_system: string;
  registered_at: string;
  status: string;
  instructions: string;
}

