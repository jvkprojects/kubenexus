import React, { useState, useEffect } from 'react';
import { clusterAPI, metricsAPI, sreAPI, auditAPI, healthAPI } from '../services/api';
import { authService } from '../services/auth';

interface DashboardMetrics {
  totalClusters: number;
  totalPods: number;
  totalNodes: number;
  totalNamespaces: number;
  healthyClusters: number;
  failedPods: number;
  activeAlerts: number;
  cpuUtilization: number;
  memoryUtilization: number;
  storageUtilization: number;
}

interface ServiceHealth {
  name: string;
  status: 'healthy' | 'unhealthy';
  responseTime?: number;
  uptime?: string;
}

interface Alert {
  id: string;
  severity: 'critical' | 'warning' | 'info';
  message: string;
  cluster?: string;
  namespace?: string;
  timestamp: string;
  resolved: boolean;
}

interface RecentEvent {
  id: string;
  type: 'Normal' | 'Warning' | 'Error';
  message: string;
  object: string;
  cluster: string;
  namespace: string;
  timestamp: string;
}

export const Dashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<DashboardMetrics>({
    totalClusters: 0,
    totalPods: 0,
    totalNodes: 0,
    totalNamespaces: 0,
    healthyClusters: 0,
    failedPods: 0,
    activeAlerts: 0,
    cpuUtilization: 0,
    memoryUtilization: 0,
    storageUtilization: 0,
  });

  const [serviceHealth, setServiceHealth] = useState<ServiceHealth[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [recentEvents, setRecentEvents] = useState<RecentEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [user, setUser] = useState(authService.getUser());

  useEffect(() => {
    loadDashboardData();
    
    // Set up auto-refresh every 30 seconds
    const interval = setInterval(loadDashboardData, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadDashboardData = async () => {
    try {
      setRefreshing(true);
      setError(null);

      // Fetch data from multiple services in parallel
      const [
        clustersResponse,
        systemMetricsResponse,
        alertsResponse,
        auditLogsResponse,
        servicesHealthResponse,
      ] = await Promise.allSettled([
        clusterAPI.getClusters(),
        metricsAPI.getSystemMetrics(),
        sreAPI.getAlerts(),
        auditAPI.getAuditLogs({ limit: 10 }),
        healthAPI.getAllServicesHealth(),
      ]);

      // Process clusters data
      if (clustersResponse.status === 'fulfilled' && clustersResponse.value.success) {
        const clusters = clustersResponse.value.data;
        
        // Calculate cluster metrics
        let totalPods = 0;
        let totalNodes = 0;
        let totalNamespaces = 0;
        let healthyClusters = 0;
        let failedPods = 0;

        // Get detailed metrics for each cluster
        if (clusters && clusters.length > 0) {
          for (const cluster of clusters) {
            try {
              const clusterMetrics = await metricsAPI.getClusterMetrics(cluster.id);
              if (clusterMetrics.success) {
                totalPods += clusterMetrics.data.total_pods || 0;
                totalNodes += clusterMetrics.data.total_nodes || 0;
                totalNamespaces += clusterMetrics.data.total_namespaces || 0;
                failedPods += clusterMetrics.data.failed_pods || 0;
                
                if (clusterMetrics.data.health_status === 'healthy') {
                  healthyClusters++;
                }
              }
            } catch (error) {
              console.error(`Error fetching metrics for cluster ${cluster.id}:`, error);
            }
          }
        }

        setMetrics(prev => ({
          ...prev,
          totalClusters: clusters?.length || 0,
          totalPods,
          totalNodes,
          totalNamespaces,
          healthyClusters,
          failedPods,
        }));
      }

      // Process system metrics
      if (systemMetricsResponse.status === 'fulfilled' && systemMetricsResponse.value.success) {
        const sysMetrics = systemMetricsResponse.value.data;
        setMetrics(prev => ({
          ...prev,
          cpuUtilization: sysMetrics.cpu_usage || 0,
          memoryUtilization: sysMetrics.memory_usage || 0,
          storageUtilization: sysMetrics.storage_usage || 0,
        }));
      }

      // Process alerts
      if (alertsResponse.status === 'fulfilled' && alertsResponse.value.success) {
        const alertsData = alertsResponse.value.data || [];
        setAlerts(alertsData);
        setMetrics(prev => ({
          ...prev,
          activeAlerts: alertsData.filter((alert: Alert) => !alert.resolved).length,
        }));
      }

      // Process recent events from audit logs
      if (auditLogsResponse.status === 'fulfilled' && auditLogsResponse.value.success) {
        const auditLogs = auditLogsResponse.value.data || [];
        const events = auditLogs.map((log: any) => ({
          id: log.id,
          type: (log.severity === 'error' ? 'Error' : log.severity === 'warning' ? 'Warning' : 'Normal') as 'Normal' | 'Warning' | 'Error',
          message: log.message,
          object: log.resource || 'System',
          cluster: log.cluster || 'N/A',
          namespace: log.namespace || 'N/A',
          timestamp: log.timestamp,
        }));
        setRecentEvents(events);
      }

      // Process service health
      if (servicesHealthResponse.status === 'fulfilled' && servicesHealthResponse.value.success) {
        setServiceHealth(servicesHealthResponse.value.data || []);
      }

    } catch (error) {
      console.error('Error loading dashboard data:', error);
      setError('Failed to load dashboard data. Please try again.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const formatUptime = (seconds: number) => {
    const days = Math.floor(seconds / (24 * 3600));
    const hours = Math.floor((seconds % (24 * 3600)) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  };

  const getHealthBadgeClass = (status: string) => {
    switch (status) {
      case 'healthy': return 'badge bg-success';
      case 'unhealthy': return 'badge bg-danger';
      default: return 'badge bg-secondary';
    }
  };

  const getAlertBadgeClass = (severity: string) => {
    switch (severity) {
      case 'critical': return 'badge bg-danger';
      case 'warning': return 'badge bg-warning';
      case 'info': return 'badge bg-info';
      default: return 'badge bg-secondary';
    }
  };

  const getEventBadgeClass = (type: string) => {
    switch (type) {
      case 'Error': return 'badge bg-danger';
      case 'Warning': return 'badge bg-warning';
      case 'Normal': return 'badge bg-success';
      default: return 'badge bg-secondary';
    }
  };

  if (loading) {
    return (
      <div className="d-flex justify-content-center align-items-center" style={{ height: '400px' }}>
        <div className="spinner-border text-primary" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard">
      {/* Header */}
      <div className="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h1 className="h3 mb-0">
            <i className="bi bi-speedometer2 me-2"></i>
            Dashboard
          </h1>
          <p className="text-muted mb-0">
            Welcome back, {user?.username || 'User'}
          </p>
        </div>
        <div>
          <button 
            className="btn btn-outline-primary me-2"
            onClick={loadDashboardData}
            disabled={refreshing}
          >
            <i className={`bi bi-arrow-clockwise ${refreshing ? 'spin' : ''}`}></i>
            {refreshing ? ' Refreshing...' : ' Refresh'}
          </button>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="alert alert-danger alert-dismissible fade show" role="alert">
          <i className="bi bi-exclamation-triangle me-2"></i>
          {error}
          <button 
            type="button" 
            className="btn-close" 
            onClick={() => setError(null)}
          ></button>
        </div>
      )}

      {/* Metrics Cards */}
      <div className="row g-3 mb-4">
        <div className="col-xl-3 col-md-6">
          <div className="card border-0 shadow-sm">
            <div className="card-body">
              <div className="d-flex align-items-center">
                <div className="flex-shrink-0">
                  <i className="bi bi-diagram-3 text-primary fs-2"></i>
                </div>
                <div className="flex-grow-1 ms-3">
                  <div className="text-muted small">Total Clusters</div>
                  <div className="h4 mb-0">{metrics.totalClusters}</div>
                  <div className="text-success small">
                    <i className="bi bi-check-circle me-1"></i>
                    {metrics.healthyClusters} healthy
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="col-xl-3 col-md-6">
          <div className="card border-0 shadow-sm">
            <div className="card-body">
              <div className="d-flex align-items-center">
                <div className="flex-shrink-0">
                  <i className="bi bi-box text-info fs-2"></i>
                </div>
                <div className="flex-grow-1 ms-3">
                  <div className="text-muted small">Total Pods</div>
                  <div className="h4 mb-0">{metrics.totalPods}</div>
                  <div className="text-danger small">
                    <i className="bi bi-exclamation-triangle me-1"></i>
                    {metrics.failedPods} failed
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="col-xl-3 col-md-6">
          <div className="card border-0 shadow-sm">
            <div className="card-body">
              <div className="d-flex align-items-center">
                <div className="flex-shrink-0">
                  <i className="bi bi-pc text-warning fs-2"></i>
                </div>
                <div className="flex-grow-1 ms-3">
                  <div className="text-muted small">Total Nodes</div>
                  <div className="h4 mb-0">{metrics.totalNodes}</div>
                  <div className="text-muted small">
                    <i className="bi bi-cpu me-1"></i>
                    {metrics.cpuUtilization}% CPU
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="col-xl-3 col-md-6">
          <div className="card border-0 shadow-sm">
            <div className="card-body">
              <div className="d-flex align-items-center">
                <div className="flex-shrink-0">
                  <i className="bi bi-exclamation-triangle text-danger fs-2"></i>
                </div>
                <div className="flex-grow-1 ms-3">
                  <div className="text-muted small">Active Alerts</div>
                  <div className="h4 mb-0">{metrics.activeAlerts}</div>
                  <div className="text-muted small">
                    <i className="bi bi-bell me-1"></i>
                    Requires attention
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="row g-4">
        {/* Service Health */}
        <div className="col-lg-6">
          <div className="card border-0 shadow-sm">
            <div className="card-header bg-transparent border-bottom">
              <h5 className="card-title mb-0">
                <i className="bi bi-heart-pulse me-2"></i>
                Service Health
              </h5>
            </div>
            <div className="card-body">
              {serviceHealth.length > 0 ? (
                <div className="list-group list-group-flush">
                  {serviceHealth.map((service) => (
                    <div key={service.name} className="list-group-item d-flex justify-content-between align-items-center px-0">
                      <div className="d-flex align-items-center">
                        <i className={`bi bi-${service.status === 'healthy' ? 'check-circle text-success' : 'x-circle text-danger'} me-2`}></i>
                        <span className="fw-medium">{service.name}</span>
                      </div>
                      <div className="text-end">
                        <span className={getHealthBadgeClass(service.status)}>
                          {service.status}
                        </span>
                        {service.responseTime && (
                          <small className="text-muted d-block">
                            {service.responseTime}ms
                          </small>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-3">
                  <i className="bi bi-info-circle text-muted fs-2"></i>
                  <p className="text-muted mb-0">No service health data available</p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Active Alerts */}
        <div className="col-lg-6">
          <div className="card border-0 shadow-sm">
            <div className="card-header bg-transparent border-bottom">
              <h5 className="card-title mb-0">
                <i className="bi bi-exclamation-triangle me-2"></i>
                Active Alerts
              </h5>
            </div>
            <div className="card-body">
              {alerts.length > 0 ? (
                <div className="list-group list-group-flush">
                  {alerts.slice(0, 5).map((alert) => (
                    <div key={alert.id} className="list-group-item px-0">
                      <div className="d-flex justify-content-between align-items-start">
                        <div className="flex-grow-1">
                          <div className="d-flex align-items-center mb-1">
                            <span className={getAlertBadgeClass(alert.severity)}>
                              {alert.severity}
                            </span>
                            <small className="text-muted ms-2">
                              {new Date(alert.timestamp).toLocaleString()}
                            </small>
                          </div>
                          <p className="mb-1">{alert.message}</p>
                          <small className="text-muted">
                            {alert.cluster && `Cluster: ${alert.cluster}`}
                            {alert.namespace && ` • Namespace: ${alert.namespace}`}
                          </small>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-3">
                  <i className="bi bi-check-circle text-success fs-2"></i>
                  <p className="text-muted mb-0">No active alerts</p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Recent Events */}
        <div className="col-12">
          <div className="card border-0 shadow-sm">
            <div className="card-header bg-transparent border-bottom">
              <h5 className="card-title mb-0">
                <i className="bi bi-journal-text me-2"></i>
                Recent Events
              </h5>
            </div>
            <div className="card-body">
              {recentEvents.length > 0 ? (
                <div className="table-responsive">
                  <table className="table table-hover">
                    <thead className="table-light">
                      <tr>
                        <th>Type</th>
                        <th>Message</th>
                        <th>Object</th>
                        <th>Cluster</th>
                        <th>Namespace</th>
                        <th>Time</th>
                      </tr>
                    </thead>
                    <tbody>
                      {recentEvents.map((event) => (
                        <tr key={event.id}>
                          <td>
                            <span className={getEventBadgeClass(event.type)}>
                              {event.type}
                            </span>
                          </td>
                          <td>{event.message}</td>
                          <td>
                            <code className="text-primary">{event.object}</code>
                          </td>
                          <td>{event.cluster}</td>
                          <td>{event.namespace}</td>
                          <td>
                            <small className="text-muted">
                              {new Date(event.timestamp).toLocaleString()}
                            </small>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="text-center py-3">
                  <i className="bi bi-info-circle text-muted fs-2"></i>
                  <p className="text-muted mb-0">No recent events</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}; 