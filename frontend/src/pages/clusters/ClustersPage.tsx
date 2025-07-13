import React, { useState, useEffect } from 'react';
import { Container, Row, Col, Card, Button, Table, Badge, Alert, Modal, Form, Spinner } from 'react-bootstrap';
import { Cluster } from '../../types';
import { clusterAPI } from '../../services/api';
import { authService } from '../../services/auth';

export function ClustersPage() {
  const [clusters, setClusters] = useState<Cluster[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [selectedCluster, setSelectedCluster] = useState<Cluster | null>(null);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    fetchClusters();
  }, []);

  const fetchClusters = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await clusterAPI.getClusters();
      
      if (response.success) {
        setClusters(response.data || []);
      } else {
        setError(response.message || 'Failed to fetch clusters');
      }
    } catch (error: any) {
      setError(error.message || 'Failed to fetch clusters');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteCluster = async () => {
    if (!selectedCluster) return;

    try {
      setDeleting(true);
      const response = await clusterAPI.deleteCluster(selectedCluster.id);
      
      if (response.success) {
        setClusters(clusters.filter(cluster => cluster.id !== selectedCluster.id));
        setShowDeleteModal(false);
        setSelectedCluster(null);
      } else {
        setError(response.message || 'Failed to delete cluster');
      }
    } catch (error: any) {
      setError(error.message || 'Failed to delete cluster');
    } finally {
      setDeleting(false);
    }
  };

  const openDeleteModal = (cluster: Cluster) => {
    setSelectedCluster(cluster);
    setShowDeleteModal(true);
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'running':
        return <Badge bg="success">Running</Badge>;
      case 'stopped':
        return <Badge bg="secondary">Stopped</Badge>;
      case 'error':
        return <Badge bg="danger">Error</Badge>;
      default:
        return <Badge bg="warning">Unknown</Badge>;
    }
  };

  if (loading) {
    return (
      <Container className="d-flex justify-content-center align-items-center" style={{ minHeight: '400px' }}>
        <Spinner animation="border" variant="primary" />
      </Container>
    );
  }

  return (
    <Container fluid>
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h1>Kubernetes Clusters</h1>
        <Button variant="primary" onClick={() => window.location.href = '/clusters/new'}>
          Create Cluster
        </Button>
      </div>

      {error && (
        <Alert variant="danger" dismissible onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Row>
        <Col>
          <Card>
            <Card.Header>
              <h5 className="mb-0">Cluster Overview</h5>
            </Card.Header>
            <Card.Body className="p-0">
              <Table responsive hover className="mb-0">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Provider</th>
                    <th>Region</th>
                    <th>Status</th>
                    <th>Nodes</th>
                    <th>Version</th>
                    <th>Created</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {clusters.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="text-center py-4">
                        <div className="text-muted">
                          <i className="bi bi-inbox" style={{ fontSize: '2rem' }}></i>
                          <p className="mt-2">No clusters found</p>
                        </div>
                      </td>
                    </tr>
                  ) : (
                    clusters.map((cluster) => (
                      <tr key={cluster.id}>
                        <td>
                          <div className="d-flex align-items-center">
                            <i className="bi bi-diagram-3 me-2 text-primary"></i>
                            <strong>{cluster.name}</strong>
                          </div>
                        </td>
                        <td>
                          <Badge bg="secondary">{cluster.provider.toUpperCase()}</Badge>
                        </td>
                        <td>{cluster.region}</td>
                        <td>{getStatusBadge(cluster.status)}</td>
                        <td>{cluster.nodeCount}</td>
                        <td>{cluster.version}</td>
                        <td>{new Date(cluster.createdAt).toLocaleDateString()}</td>
                        <td>
                          <div className="d-flex gap-2">
                            <Button
                              variant="outline-primary"
                              size="sm"
                              onClick={() => window.location.href = `/clusters/${cluster.id}`}
                            >
                              <i className="bi bi-eye"></i>
                            </Button>
                            <Button
                              variant="outline-secondary"
                              size="sm"
                              onClick={() => window.location.href = `/clusters/${cluster.id}/edit`}
                            >
                              <i className="bi bi-pencil"></i>
                            </Button>
                            {authService.hasPermission('cluster:delete') && (
                              <Button
                                variant="outline-danger"
                                size="sm"
                                onClick={() => openDeleteModal(cluster)}
                              >
                                <i className="bi bi-trash"></i>
                              </Button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </Table>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Delete Confirmation Modal */}
      <Modal show={showDeleteModal} onHide={() => setShowDeleteModal(false)} centered>
        <Modal.Header closeButton>
          <Modal.Title>Confirm Delete</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p>Are you sure you want to delete the cluster <strong>{selectedCluster?.name}</strong>?</p>
          <p className="text-danger">
            <i className="bi bi-exclamation-triangle me-2"></i>
            This action cannot be undone and will permanently delete all resources in the cluster.
          </p>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowDeleteModal(false)} disabled={deleting}>
            Cancel
          </Button>
          <Button variant="danger" onClick={handleDeleteCluster} disabled={deleting}>
            {deleting ? (
              <>
                <Spinner size="sm" className="me-2" />
                Deleting...
              </>
            ) : (
              'Delete Cluster'
            )}
          </Button>
        </Modal.Footer>
      </Modal>
    </Container>
  );
} 