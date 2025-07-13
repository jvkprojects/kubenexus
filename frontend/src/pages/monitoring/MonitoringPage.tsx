import React, { useState, useEffect } from 'react';
import { Container, Row, Col, Card, Badge, Table, Alert, Tab, Tabs } from 'react-bootstrap';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';
import { ClusterMetrics, Alert as AlertType } from '../../types';
import { apiService } from '../../services/api';

export function MonitoringPage() {
  const [alerts, setAlerts] = useState<AlertType[]>([]);
  const [metrics, setMetrics] = useState<ClusterMetrics[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    fetchMonitoringData();
  }, []);

  const fetchMonitoringData = async () => {
    try {
      const [alertsResponse, metricsResponse] = await Promise.all([
        apiService.get<AlertType[]>('/alerts'),
        apiService.get<ClusterMetrics[]>('/monitoring/metrics'),
      ]);

      if (alertsResponse.success) setAlerts(alertsResponse.data || []);
      if (metricsResponse.success) setMetrics(metricsResponse.data || []);
    } catch (error) {
      console.error('Failed to fetch monitoring data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <Badge bg="danger">Critical</Badge>;
      case 'warning':
        return <Badge bg="warning">Warning</Badge>;
      case 'info':
        return <Badge bg="info">Info</Badge>;
      default:
        return <Badge bg="secondary">{severity}</Badge>;
    }
  };

  // Mock data for SRE recommendations
  const sreRecommendations = [
    {
      id: '1',
      type: 'cost-optimization',
      title: 'Optimize EC2 Instance Types',
      description: 'Switch to more cost-effective instance types to save 25% on monthly costs',
      impact: 'high',
      savings: '$1,200/month',
    },
    {
      id: '2',
      type: 'performance',
      title: 'Scale Down Unused Pods',
      description: 'Detected 15 pods with low utilization that can be scaled down',
      impact: 'medium',
      savings: '$400/month',
    },
    {
      id: '3',
      type: 'security',
      title: 'Update Kubernetes Version',
      description: 'Cluster version 1.24.x has security vulnerabilities, upgrade to 1.28.x',
      impact: 'high',
      risk: 'High Security Risk',
    },
  ];

  // Mock anomaly detection data
  const anomalies = [
    {
      timestamp: '2024-01-15 14:30',
      type: 'CPU Spike',
      cluster: 'prod-east-1',
      severity: 'warning',
      description: 'CPU usage increased by 300% in 5 minutes',
    },
    {
      timestamp: '2024-01-15 13:15',
      type: 'Memory Leak',
      cluster: 'staging-west-2',
      severity: 'critical',
      description: 'Memory usage consistently increasing without cleanup',
    },
    {
      timestamp: '2024-01-15 12:00',
      type: 'Network Latency',
      cluster: 'prod-east-1',
      severity: 'info',
      description: 'Inter-pod communication latency above baseline',
    },
  ];

  // Mock performance metrics for charts
  const performanceData = [
    { time: '00:00', cpu: 45, memory: 62, network: 30, pods: 120 },
    { time: '04:00', cpu: 52, memory: 58, network: 35, pods: 118 },
    { time: '08:00', cpu: 78, memory: 72, network: 85, pods: 125 },
    { time: '12:00', cpu: 85, memory: 80, network: 90, pods: 130 },
    { time: '16:00', cpu: 72, memory: 68, network: 70, pods: 128 },
    { time: '20:00', cpu: 58, memory: 55, network: 45, pods: 122 },
  ];

  const clusterUsageData = [
    { cluster: 'prod-east-1', cpu: 85, memory: 72, storage: 45 },
    { cluster: 'prod-west-2', cpu: 62, memory: 58, storage: 38 },
    { cluster: 'staging-east', cpu: 45, memory: 42, storage: 25 },
    { cluster: 'dev-cluster', cpu: 35, memory: 32, storage: 18 },
  ];

  return (
    <Container fluid>
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h1>🤖 SRE Agent Monitoring</h1>
        <Badge bg="success">AI Monitoring Active</Badge>
      </div>

      {/* Critical Alerts */}
      {alerts.filter(a => a.severity === 'critical' && !a.resolved).length > 0 && (
        <Alert variant="danger" className="mb-4">
          <Alert.Heading>🚨 Critical Alerts Detected</Alert.Heading>
          <p>
            {alerts.filter(a => a.severity === 'critical' && !a.resolved).length} critical issues require immediate attention.
          </p>
        </Alert>
      )}

      <Tabs
        activeKey={activeTab}
        onSelect={(k) => setActiveTab(k || 'overview')}
        className="mb-4"
      >
        <Tab eventKey="overview" title="📊 Overview">
          <Row className="mb-4">
            {/* Performance Metrics */}
            <Col lg={8} className="mb-4">
              <Card>
                <Card.Header>
                  <h5 className="mb-0">Real-time Performance Metrics</h5>
                </Card.Header>
                <Card.Body>
                  <ResponsiveContainer width="100%" height={300}>
                    <LineChart data={performanceData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="time" />
                      <YAxis />
                      <Tooltip />
                      <Line type="monotone" dataKey="cpu" stroke="#dc3545" name="CPU %" />
                      <Line type="monotone" dataKey="memory" stroke="#ffc107" name="Memory %" />
                      <Line type="monotone" dataKey="network" stroke="#17a2b8" name="Network %" />
                    </LineChart>
                  </ResponsiveContainer>
                </Card.Body>
              </Card>
            </Col>

            {/* Cluster Usage */}
            <Col lg={4} className="mb-4">
              <Card>
                <Card.Header>
                  <h5 className="mb-0">Cluster Resource Usage</h5>
                </Card.Header>
                <Card.Body>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={clusterUsageData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="cluster" />
                      <YAxis />
                      <Tooltip />
                      <Bar dataKey="cpu" fill="#8884d8" name="CPU %" />
                      <Bar dataKey="memory" fill="#82ca9d" name="Memory %" />
                      <Bar dataKey="storage" fill="#ffc658" name="Storage %" />
                    </BarChart>
                  </ResponsiveContainer>
                </Card.Body>
              </Card>
            </Col>
          </Row>
        </Tab>

        <Tab eventKey="recommendations" title="💡 AI Recommendations">
          <Row>
            {sreRecommendations.map((rec) => (
              <Col lg={4} key={rec.id} className="mb-4">
                <Card className="h-100">
                  <Card.Header className="d-flex justify-content-between">
                    <span>{rec.type === 'cost-optimization' ? '💰' : rec.type === 'performance' ? '⚡' : '🔒'}</span>
                    <Badge bg={rec.impact === 'high' ? 'danger' : rec.impact === 'medium' ? 'warning' : 'info'}>
                      {rec.impact} impact
                    </Badge>
                  </Card.Header>
                  <Card.Body>
                    <h6>{rec.title}</h6>
                    <p className="text-muted small">{rec.description}</p>
                    {rec.savings && (
                      <div className="text-success fw-bold">💰 Savings: {rec.savings}</div>
                    )}
                    {rec.risk && (
                      <div className="text-danger fw-bold">⚠️ {rec.risk}</div>
                    )}
                  </Card.Body>
                </Card>
              </Col>
            ))}
          </Row>
        </Tab>

        <Tab eventKey="anomalies" title="🔍 Anomaly Detection">
          <Card>
            <Card.Header>
              <h5 className="mb-0">AI-Detected Anomalies</h5>
            </Card.Header>
            <Card.Body className="p-0">
              <Table responsive className="mb-0">
                <thead className="table-light">
                  <tr>
                    <th>Timestamp</th>
                    <th>Type</th>
                    <th>Cluster</th>
                    <th>Severity</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {anomalies.map((anomaly, index) => (
                    <tr key={index}>
                      <td>{anomaly.timestamp}</td>
                      <td>
                        <span className="fw-bold">{anomaly.type}</span>
                      </td>
                      <td>{anomaly.cluster}</td>
                      <td>{getSeverityBadge(anomaly.severity)}</td>
                      <td>{anomaly.description}</td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Card.Body>
          </Card>
        </Tab>

        <Tab eventKey="alerts" title="🚨 Alerts">
          <Card>
            <Card.Header>
              <h5 className="mb-0">Active Alerts</h5>
            </Card.Header>
            <Card.Body>
              {alerts.length === 0 ? (
                <div className="text-center py-4">
                  <h6 className="text-muted">No active alerts</h6>
                  <p className="text-muted">All systems are running normally</p>
                </div>
              ) : (
                alerts.map((alert) => (
                  <div key={alert.id} className="border-bottom py-3">
                    <div className="d-flex justify-content-between align-items-start">
                      <div className="d-flex align-items-start">
                        {getSeverityBadge(alert.severity)}
                        <div className="ms-3">
                          <h6 className="mb-1">{alert.title}</h6>
                          <p className="mb-1 text-muted">{alert.message}</p>
                          <small className="text-muted">
                            {new Date(alert.timestamp).toLocaleString()}
                            {alert.clusterId && ` • Cluster: ${alert.clusterId}`}
                          </small>
                        </div>
                      </div>
                      <Badge bg={alert.resolved ? 'success' : 'secondary'}>
                        {alert.resolved ? 'Resolved' : 'Active'}
                      </Badge>
                    </div>
                  </div>
                ))
              )}
            </Card.Body>
          </Card>
        </Tab>
      </Tabs>
    </Container>
  );
} 