import React, { useState, useEffect } from 'react';
import { Container, Row, Col, Card, Table, Badge, Form, InputGroup, Spinner } from 'react-bootstrap';
import { AuditLog } from '../../types';
import { apiService } from '../../services/api';

export function AuditLogsPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [actionFilter, setActionFilter] = useState('all');
  const [userFilter, setUserFilter] = useState('all');

  useEffect(() => {
    fetchAuditLogs();
  }, []);

  const fetchAuditLogs = async () => {
    try {
      const response = await apiService.get<AuditLog[]>('/audit-logs');
      if (response.success) {
        setLogs(response.data || []);
      }
    } catch (error) {
      console.error('Failed to fetch audit logs:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredLogs = logs.filter(log => {
    const matchesSearch = log.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         log.resource.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         log.username.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesAction = actionFilter === 'all' || log.action === actionFilter;
    const matchesUser = userFilter === 'all' || log.username === userFilter;
    return matchesSearch && matchesAction && matchesUser;
  });

  const getActionBadge = (action: string, success: boolean) => {
    const actionColors: Record<string, string> = {
      'create': 'success',
      'update': 'warning',
      'delete': 'danger',
      'login': 'info',
      'logout': 'secondary',
    };

    const baseColor = actionColors[action.toLowerCase()] || 'primary';
    const variant = success ? baseColor : 'danger';

    return (
      <Badge bg={variant}>
        {action} {!success && '(Failed)'}
      </Badge>
    );
  };

  const uniqueActions = [...new Set(logs.map(log => log.action))];
  const uniqueUsers = [...new Set(logs.map(log => log.username))];

  if (loading) {
    return (
      <div className="d-flex justify-content-center align-items-center" style={{ height: '400px' }}>
        <Spinner animation="border" variant="primary" />
      </div>
    );
  }

  return (
    <Container fluid>
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h1>📝 Audit Logs</h1>
        <Badge bg="info">
          {logs.length} total events
        </Badge>
      </div>

      {/* Stats Cards */}
      <Row className="mb-4">
        <Col lg={3} md={6} className="mb-3">
          <Card className="card-hover h-100">
            <Card.Body>
              <div className="d-flex align-items-center">
                <div className="me-3" style={{ fontSize: '2rem' }}>📊</div>
                <div>
                  <h6 className="text-muted mb-0">Total Events</h6>
                  <h3 className="mb-0">{logs.length}</h3>
                </div>
              </div>
            </Card.Body>
          </Card>
        </Col>
        <Col lg={3} md={6} className="mb-3">
          <Card className="card-hover h-100">
            <Card.Body>
              <div className="d-flex align-items-center">
                <div className="me-3" style={{ fontSize: '2rem' }}>✅</div>
                <div>
                  <h6 className="text-muted mb-0">Successful</h6>
                  <h3 className="mb-0">{logs.filter(l => l.success).length}</h3>
                </div>
              </div>
            </Card.Body>
          </Card>
        </Col>
        <Col lg={3} md={6} className="mb-3">
          <Card className="card-hover h-100">
            <Card.Body>
              <div className="d-flex align-items-center">
                <div className="me-3" style={{ fontSize: '2rem' }}>❌</div>
                <div>
                  <h6 className="text-muted mb-0">Failed</h6>
                  <h3 className="mb-0">{logs.filter(l => !l.success).length}</h3>
                </div>
              </div>
            </Card.Body>
          </Card>
        </Col>
        <Col lg={3} md={6} className="mb-3">
          <Card className="card-hover h-100">
            <Card.Body>
              <div className="d-flex align-items-center">
                <div className="me-3" style={{ fontSize: '2rem' }}>👥</div>
                <div>
                  <h6 className="text-muted mb-0">Unique Users</h6>
                  <h3 className="mb-0">{uniqueUsers.length}</h3>
                </div>
              </div>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Filters */}
      <Card className="mb-4">
        <Card.Body>
          <Row className="g-3">
            <Col md={4}>
              <InputGroup>
                <InputGroup.Text>🔍</InputGroup.Text>
                <Form.Control
                  type="text"
                  placeholder="Search logs..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </InputGroup>
            </Col>
            <Col md={3}>
              <Form.Select
                value={actionFilter}
                onChange={(e) => setActionFilter(e.target.value)}
              >
                <option value="all">All Actions</option>
                {uniqueActions.map(action => (
                  <option key={action} value={action}>{action}</option>
                ))}
              </Form.Select>
            </Col>
            <Col md={3}>
              <Form.Select
                value={userFilter}
                onChange={(e) => setUserFilter(e.target.value)}
              >
                <option value="all">All Users</option>
                {uniqueUsers.map(user => (
                  <option key={user} value={user}>{user}</option>
                ))}
              </Form.Select>
            </Col>
            <Col md={2}>
              <div className="text-muted">
                {filteredLogs.length} events
              </div>
            </Col>
          </Row>
        </Card.Body>
      </Card>

      {/* Audit Logs Table */}
      <Card>
        <Card.Body className="p-0">
          <Table responsive className="mb-0">
            <thead className="table-light">
              <tr>
                <th>Timestamp</th>
                <th>User</th>
                <th>Action</th>
                <th>Resource</th>
                <th>IP Address</th>
                <th>Status</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {filteredLogs.map((log) => (
                <tr key={log.id}>
                  <td>
                    <div>
                      {new Date(log.timestamp).toLocaleDateString()}
                    </div>
                    <small className="text-muted">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </small>
                  </td>
                  <td>
                    <div className="fw-bold">{log.username}</div>
                    <small className="text-muted">ID: {log.userId.slice(0, 8)}</small>
                  </td>
                  <td>
                    {getActionBadge(log.action, log.success)}
                  </td>
                  <td>
                    <div>{log.resource}</div>
                    {log.resourceId && (
                      <small className="text-muted">ID: {log.resourceId.slice(0, 8)}</small>
                    )}
                  </td>
                  <td>
                    <code className="small">{log.ipAddress}</code>
                  </td>
                  <td>
                    <Badge bg={log.success ? 'success' : 'danger'}>
                      {log.success ? 'Success' : 'Failed'}
                    </Badge>
                  </td>
                  <td>
                    {log.details ? (
                      <small className="text-muted">
                        {typeof log.details === 'string' 
                          ? log.details 
                          : JSON.stringify(log.details).substring(0, 50) + '...'
                        }
                      </small>
                    ) : (
                      <span className="text-muted">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
          
          {filteredLogs.length === 0 && (
            <div className="text-center py-5">
              <h5 className="text-muted">No audit logs found</h5>
              <p className="text-muted">No events match your current filters</p>
            </div>
          )}
        </Card.Body>
      </Card>
    </Container>
  );
} 