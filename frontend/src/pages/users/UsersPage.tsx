import React, { useState, useEffect } from 'react';
import { Container, Row, Col, Card, Table, Button, Badge, Form, InputGroup, Modal, Spinner } from 'react-bootstrap';
import { User } from '../../types';
import { apiService } from '../../services/api';

export function UsersPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [roleFilter, setRoleFilter] = useState('all');
  const [showUserModal, setShowUserModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [isEditing, setIsEditing] = useState(false);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      const response = await apiService.get<User[]>('/users');
      if (response.success) {
        setUsers(response.data || []);
      }
    } catch (error) {
      console.error('Failed to fetch users:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteUser = async (userId: string) => {
    if (window.confirm('Are you sure you want to delete this user?')) {
      try {
        const response = await apiService.delete(`/users/${userId}`);
        if (response.success) {
          setUsers(users.filter(u => u.id !== userId));
        }
      } catch (error) {
        console.error('Failed to delete user:', error);
      }
    }
  };

  const handleEditUser = (user: User) => {
    setSelectedUser(user);
    setIsEditing(true);
    setShowUserModal(true);
  };

  const handleCreateUser = () => {
    setSelectedUser(null);
    setIsEditing(false);
    setShowUserModal(true);
  };

  const filteredUsers = users.filter(user => {
    const matchesSearch = user.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         user.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         user.firstName.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         user.lastName.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesRole = roleFilter === 'all' || user.roles.includes(roleFilter);
    return matchesSearch && matchesRole;
  });

  const getRoleBadges = (roles: string[]) => {
    const roleColors: Record<string, string> = {
      admin: 'danger',
      'user-manager': 'warning',
      'cluster-manager': 'info',
      user: 'secondary',
    };

    return roles.map(role => (
      <Badge key={role} bg={roleColors[role] || 'secondary'} className="me-1">
        {role}
      </Badge>
    ));
  };

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
        <h1>User Management</h1>
        <Button variant="primary" onClick={handleCreateUser}>
          ➕ Add User
        </Button>
      </div>

      {/* Stats Cards */}
      <Row className="mb-4">
        <Col lg={3} md={6} className="mb-3">
          <Card className="card-hover h-100">
            <Card.Body>
              <div className="d-flex align-items-center">
                <div className="me-3" style={{ fontSize: '2rem' }}>👥</div>
                <div>
                  <h6 className="text-muted mb-0">Total Users</h6>
                  <h3 className="mb-0">{users.length}</h3>
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
                  <h6 className="text-muted mb-0">Active Users</h6>
                  <h3 className="mb-0">{users.filter(u => u.isActive).length}</h3>
                </div>
              </div>
            </Card.Body>
          </Card>
        </Col>
        <Col lg={3} md={6} className="mb-3">
          <Card className="card-hover h-100">
            <Card.Body>
              <div className="d-flex align-items-center">
                <div className="me-3" style={{ fontSize: '2rem' }}>👑</div>
                <div>
                  <h6 className="text-muted mb-0">Administrators</h6>
                  <h3 className="mb-0">{users.filter(u => u.roles.includes('admin')).length}</h3>
                </div>
              </div>
            </Card.Body>
          </Card>
        </Col>
        <Col lg={3} md={6} className="mb-3">
          <Card className="card-hover h-100">
            <Card.Body>
              <div className="d-flex align-items-center">
                <div className="me-3" style={{ fontSize: '2rem' }}>🔒</div>
                <div>
                  <h6 className="text-muted mb-0">Inactive Users</h6>
                  <h3 className="mb-0">{users.filter(u => !u.isActive).length}</h3>
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
            <Col md={6}>
              <InputGroup>
                <InputGroup.Text>🔍</InputGroup.Text>
                <Form.Control
                  type="text"
                  placeholder="Search users..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </InputGroup>
            </Col>
            <Col md={3}>
              <Form.Select
                value={roleFilter}
                onChange={(e) => setRoleFilter(e.target.value)}
              >
                <option value="all">All Roles</option>
                <option value="admin">Admin</option>
                <option value="user-manager">User Manager</option>
                <option value="cluster-manager">Cluster Manager</option>
                <option value="user">User</option>
              </Form.Select>
            </Col>
            <Col md={3}>
              <div className="text-muted">
                Found {filteredUsers.length} of {users.length} users
              </div>
            </Col>
          </Row>
        </Card.Body>
      </Card>

      {/* Users Table */}
      <Card>
        <Card.Body className="p-0">
          <Table responsive className="mb-0">
            <thead className="table-light">
              <tr>
                <th>User</th>
                <th>Username</th>
                <th>Email</th>
                <th>Roles</th>
                <th>Status</th>
                <th>Last Login</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredUsers.map((user) => (
                <tr key={user.id}>
                  <td>
                    <div className="d-flex align-items-center">
                      <div
                        className="bg-primary rounded-circle d-flex align-items-center justify-content-center me-3"
                        style={{ width: '40px', height: '40px', color: 'white' }}
                      >
                        {user.firstName.charAt(0)}{user.lastName.charAt(0)}
                      </div>
                      <div>
                        <div className="fw-bold">{user.firstName} {user.lastName}</div>
                        <small className="text-muted">ID: {user.id.slice(0, 8)}</small>
                      </div>
                    </div>
                  </td>
                  <td>{user.username}</td>
                  <td>{user.email}</td>
                  <td>{getRoleBadges(user.roles)}</td>
                  <td>
                    <Badge bg={user.isActive ? 'success' : 'secondary'}>
                      {user.isActive ? 'Active' : 'Inactive'}
                    </Badge>
                  </td>
                  <td>
                    {user.lastLogin 
                      ? new Date(user.lastLogin).toLocaleDateString()
                      : 'Never'
                    }
                  </td>
                  <td>{new Date(user.createdAt).toLocaleDateString()}</td>
                  <td>
                    <div className="d-flex gap-1">
                      <Button
                        variant="outline-primary"
                        size="sm"
                        onClick={() => handleEditUser(user)}
                      >
                        ✏️
                      </Button>
                      <Button
                        variant="outline-danger"
                        size="sm"
                        onClick={() => handleDeleteUser(user.id)}
                      >
                        🗑️
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
          
          {filteredUsers.length === 0 && (
            <div className="text-center py-5">
              <h5 className="text-muted">No users found</h5>
              <p className="text-muted">Create your first user to get started</p>
              <Button variant="primary" onClick={handleCreateUser}>
                Add User
              </Button>
            </div>
          )}
        </Card.Body>
      </Card>

      {/* User Modal (placeholder - would contain form) */}
      <Modal show={showUserModal} onHide={() => setShowUserModal(false)} size="lg">
        <Modal.Header closeButton>
          <Modal.Title>{isEditing ? 'Edit User' : 'Create User'}</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p>User form would go here with fields for:</p>
          <ul>
            <li>Username</li>
            <li>Email</li>
            <li>First Name</li>
            <li>Last Name</li>
            <li>Password (for new users)</li>
            <li>Roles (checkboxes)</li>
            <li>Active status</li>
          </ul>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowUserModal(false)}>
            Cancel
          </Button>
          <Button variant="primary">
            {isEditing ? 'Update User' : 'Create User'}
          </Button>
        </Modal.Footer>
      </Modal>
    </Container>
  );
} 