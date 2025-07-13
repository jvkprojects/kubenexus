import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Container, Row, Col, Card, Badge, Button, Table, Tab, Tabs, Spinner } from 'react-bootstrap';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Cluster, ClusterMetrics } from '../../types';
import { clusterAPI } from '../../services/api';

export function ClusterDetails() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [cluster, setCluster] = useState<Cluster | null>(null);
  const [metrics, setMetrics] = useState<ClusterMetrics[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    if (id) {
      fetchClusterDetails(id);
      fetchClusterMetrics(id);
    }
  }, [id]);

  const fetchClusterDetails = async (clusterId: string) => {
    try {
      const response = await clusterAPI.getCluster(clusterId);
      if (response.success) {
        setCluster(response.data!);
      }
    } catch (error) {
      console.error('Failed to fetch cluster details:', error);
    }
  };

  const fetchClusterMetrics = async (clusterId: string) => {
    try {
      const response = await clusterAPI.getClusterMetrics?.(clusterId);
      if (response?.success) {
        setMetrics(response.data || []);
      }
    } catch (error) {
      console.error('Failed to fetch cluster metrics:', error);
    } finally {
      setLoading(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'active':
        return <Badge bg="success">Active</Badge>;
      case 'inactive':
        return <Badge bg="warning">Inactive</Badge>;
      case 'error':
        return <Badge bg="danger">Error</Badge>;
      default:
        return <Badge bg="secondary">{status}</Badge>;
    }
  };

  const getProviderIcon = (provider: string) => {
    switch (provider) {
      case 'aws':
        return '☁️ AWS';
      case 'gcp':
        return '☁️ GCP';
      case 'azure':
        return '☁️ Azure';
      default:
        return '🖥️ On-premises';
    }
  };

  if (loading) {
    return (
      <Container className="mt-5 text-center">
        <Spinner animation="border" />
        <p className="mt-3">Loading cluster details...</p>
      </Container>
    );
  }

  if (!cluster) {
    return (
      <Container className="mt-5">
        <div className="text-center">
          <h4>Cluster not found</h4>
          <Button variant="primary" onClick={() => navigate('/clusters')}>
            Back to Clusters
          </Button>
        </div>
      </Container>
    );
  }

  return (
    <Container fluid>
      <Row className="mb-4">
        <Col>
          <div className="d-flex justify-content-between align-items-center">
            <div>
              <h2 className="mb-1">{cluster.name}</h2>
              <div className="d-flex align-items-center gap-3">
                {getStatusBadge(cluster.status)}
                <span className="text-muted">{getProviderIcon(cluster.provider)}</span>
                <span className="text-muted">Region: {cluster.region}</span>
                <span className="text-muted">Version: {cluster.version}</span>
              </div>
            </div>
            <div>
              <Button variant="outline-secondary" className="me-2" onClick={() => navigate('/clusters')}>
                <i className="bi bi-arrow-left me-2"></i>Back
              </Button>
              <Button variant="primary">
                <i className="bi bi-gear me-2"></i>Settings
              </Button>
            </div>
          </div>
        </Col>
      </Row>

      <Row className="mb-4">
        <Col md={3}>
          <Card>
            <Card.Body className="text-center">
              <h3 className="text-primary mb-1">{cluster.nodeCount || cluster.nodes || 0}</h3>
              <h6 className="text-muted mb-0">Nodes</h6>
            </Card.Body>
          </Card>
        </Col>
        <Col md={3}>
          <Card>
            <Card.Body className="text-center">
              <h3 className="text-success mb-1">{cluster.runningPods || cluster.totalPods || 0}</h3>
              <h6 className="text-muted mb-0">Running Pods</h6>
            </Card.Body>
          </Card>
        </Col>
        <Col md={3}>
          <Card>
            <Card.Body className="text-center">
              <h3 className="text-info mb-1">{cluster.resourceUsage?.cpu || cluster.cpuUsage || 0}%</h3>
              <h6 className="text-muted mb-0">CPU Usage</h6>
            </Card.Body>
          </Card>
        </Col>
        <Col md={3}>
          <Card>
            <Card.Body className="text-center">
              <h3 className="text-warning mb-1">{cluster.resourceUsage?.memory || cluster.memoryUsage || 0}%</h3>
              <h6 className="text-muted mb-0">Memory Usage</h6>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      <Row className="mb-4">
        <Col md={6}>
          <Card>
            <Card.Header>
              <h5 className="mb-0">Cluster Information</h5>
            </Card.Header>
            <Card.Body>
              <Table borderless>
                <tbody>
                  <tr>
                    <td><strong>Provider:</strong></td>
                    <td>{getProviderIcon(cluster.provider)}</td>
                  </tr>
                  <tr>
                    <td><strong>Region:</strong></td>
                    <td>{cluster.region}</td>
                  </tr>
                  <tr>
                    <td><strong>Kubernetes Version:</strong></td>
                    <td>{cluster.kubernetesVersion || cluster.version}</td>
                  </tr>
                  <tr>
                    <td><strong>Environment:</strong></td>
                    <td>{cluster.environment || 'Production'}</td>
                  </tr>
                  <tr>
                    <td><strong>Monthly Cost:</strong></td>
                    <td>${cluster.cost || 0}</td>
                  </tr>
                  <tr>
                    <td><strong>Created:</strong></td>
                    <td>{new Date(cluster.createdAt).toLocaleDateString()}</td>
                  </tr>
                  <tr>
                    <td><strong>Last Updated:</strong></td>
                    <td>{new Date(cluster.updatedAt).toLocaleDateString()}</td>
                  </tr>
                </tbody>
              </Table>
            </Card.Body>
          </Card>
        </Col>
        <Col md={6}>
          <Card>
            <Card.Header>
              <h5 className="mb-0">Resource Usage</h5>
            </Card.Header>
            <Card.Body>
              <div className="mb-3">
                <div className="d-flex justify-content-between mb-1">
                  <span>CPU Usage</span>
                  <span>{cluster.resourceUsage?.cpu || cluster.cpuUsage || 0}%</span>
                </div>
                <div className="progress">
                  <div
                    className="progress-bar"
                    style={{ width: `${cluster.resourceUsage?.cpu || cluster.cpuUsage || 0}%` }}
                  />
                </div>
              </div>
              <div className="mb-3">
                <div className="d-flex justify-content-between mb-1">
                  <span>Memory Usage</span>
                  <span>{cluster.resourceUsage?.memory || cluster.memoryUsage || 0}%</span>
                </div>
                <div className="progress">
                  <div
                    className="progress-bar bg-warning"
                    style={{ width: `${cluster.resourceUsage?.memory || cluster.memoryUsage || 0}%` }}
                  />
                </div>
              </div>
              <div className="mb-3">
                <div className="d-flex justify-content-between mb-1">
                  <span>Storage Usage</span>
                  <span>{cluster.resourceUsage?.storage || cluster.storageUsage || 0}GB</span>
                </div>
                <div className="progress">
                  <div
                    className="progress-bar bg-info"
                    style={{ width: `${Math.min((cluster.resourceUsage?.storage || cluster.storageUsage || 0) / 100 * 100, 100)}%` }}
                  />
                </div>
              </div>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      <Tabs
        activeKey={activeTab}
        onSelect={(k) => setActiveTab(k || 'overview')}
        className="mb-3"
      >
        <Tab eventKey="overview" title="Overview">
          <Row>
            <Col md={12}>
              <Card>
                <Card.Header>
                  <h5 className="mb-0">Cluster Metrics</h5>
                </Card.Header>
                <Card.Body>
                  {metrics.length > 0 ? (
                    <ResponsiveContainer width="100%" height={300}>
                      <LineChart data={metrics}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis dataKey="timestamp" />
                        <YAxis />
                        <Tooltip />
                        <Line type="monotone" dataKey="cpuUsage" stroke="#8884d8" name="CPU Usage %" />
                        <Line type="monotone" dataKey="memoryUsage" stroke="#82ca9d" name="Memory Usage %" />
                      </LineChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="text-center text-muted py-5">
                      <p>No metrics data available</p>
                    </div>
                  )}
                </Card.Body>
              </Card>
            </Col>
          </Row>
        </Tab>
        <Tab eventKey="nodes" title="Nodes">
          <Card>
            <Card.Header>
              <h5 className="mb-0">Cluster Nodes</h5>
            </Card.Header>
            <Card.Body>
              <div className="text-center text-muted py-5">
                <p>Node information will be loaded from the cluster manager service</p>
              </div>
            </Card.Body>
          </Card>
        </Tab>
        <Tab eventKey="pods" title="Pods">
          <Card>
            <Card.Header>
              <h5 className="mb-0">Running Pods</h5>
            </Card.Header>
            <Card.Body>
              <div className="text-center text-muted py-5">
                <p>Pod information will be loaded from the cluster manager service</p>
              </div>
            </Card.Body>
          </Card>
        </Tab>
        <Tab eventKey="services" title="Services">
          <Card>
            <Card.Header>
              <h5 className="mb-0">Services</h5>
            </Card.Header>
            <Card.Body>
              <div className="text-center text-muted py-5">
                <p>Service information will be loaded from the cluster manager service</p>
              </div>
            </Card.Body>
          </Card>
        </Tab>
      </Tabs>
    </Container>
  );
} 