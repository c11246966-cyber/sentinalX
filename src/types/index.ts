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
