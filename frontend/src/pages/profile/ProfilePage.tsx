import React, { useState } from 'react';
import { Container, Row, Col, Card, Form, Button, Tab, Tabs, Alert } from 'react-bootstrap';
import { useAuth } from '../../contexts/AuthContext';
import { authService } from '../../services/auth';
import { authAPI } from '../../services/api';

export function ProfilePage() {
  const { user, updateUser } = useAuth();
  const [activeTab, setActiveTab] = useState('profile');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const [profileData, setProfileData] = useState({
    firstName: user?.firstName || '',
    lastName: user?.lastName || '',
    email: user?.email || '',
  });

  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  });

  const handleProfileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setProfileData({
      ...profileData,
      [e.target.name]: e.target.value,
    });
  };

  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setPasswordData({
      ...passwordData,
      [e.target.name]: e.target.value,
    });
  };

  const handleProfileSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');
    setError('');

    try {
      // Here you would call an API to update the profile
      // For now, we'll simulate success
      setTimeout(() => {
        setMessage('Profile updated successfully!');
        setLoading(false);
        // Update the user context with new data
        if (user) {
          updateUser({
            ...user,
            firstName: profileData.firstName,
            lastName: profileData.lastName,
            email: profileData.email,
          });
        }
      }, 1000);
    } catch (err: any) {
      setError(err.message || 'Failed to update profile');
      setLoading(false);
    }
  };

  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');
    setError('');

    if (passwordData.newPassword !== passwordData.confirmPassword) {
      setError('New passwords do not match');
      setLoading(false);
      return;
    }

    if (passwordData.newPassword.length < 8) {
      setError('Password must be at least 8 characters long');
      setLoading(false);
      return;
    }

    try {
      const response = await authAPI.changePassword({
        currentPassword: passwordData.currentPassword,
        newPassword: passwordData.newPassword
      });

      if (response.success) {
        setMessage('Password changed successfully!');
        setPasswordData({
          currentPassword: '',
          newPassword: '',
          confirmPassword: '',
        });
      } else {
        setError(response.message || 'Failed to change password');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to change password');
    } finally {
      setLoading(false);
    }
  };

  if (!user) {
    return (
      <Container>
        <div className="text-center py-5">
          <h3>Profile not available</h3>
          <p>Please log in to view your profile.</p>
        </div>
      </Container>
    );
  }

  return (
    <Container fluid>
      <div className="mb-4">
        <h1>👤 Profile Settings</h1>
        <p className="text-muted">Manage your account settings and preferences</p>
      </div>

      {message && (
        <Alert variant="success" dismissible onClose={() => setMessage('')}>
          {message}
        </Alert>
      )}

      {error && (
        <Alert variant="danger" dismissible onClose={() => setError('')}>
          {error}
        </Alert>
      )}

      <Row>
        <Col lg={8}>
          <Tabs
            activeKey={activeTab}
            onSelect={(k) => setActiveTab(k || 'profile')}
            className="mb-3"
          >
            <Tab eventKey="profile" title="👤 Profile Information">
              <Card>
                <Card.Header>
                  <h5 className="mb-0">Personal Information</h5>
                </Card.Header>
                <Card.Body>
                  <Form onSubmit={handleProfileSubmit}>
                    <Row>
                      <Col md={6}>
                        <Form.Group className="mb-3">
                          <Form.Label>First Name</Form.Label>
                          <Form.Control
                            type="text"
                            name="firstName"
                            value={profileData.firstName}
                            onChange={handleProfileChange}
                            required
                          />
                        </Form.Group>
                      </Col>
                      <Col md={6}>
                        <Form.Group className="mb-3">
                          <Form.Label>Last Name</Form.Label>
                          <Form.Control
                            type="text"
                            name="lastName"
                            value={profileData.lastName}
                            onChange={handleProfileChange}
                            required
                          />
                        </Form.Group>
                      </Col>
                    </Row>

                    <Form.Group className="mb-3">
                      <Form.Label>Email Address</Form.Label>
                      <Form.Control
                        type="email"
                        name="email"
                        value={profileData.email}
                        onChange={handleProfileChange}
                        required
                      />
                    </Form.Group>

                    <Form.Group className="mb-3">
                      <Form.Label>Username</Form.Label>
                      <Form.Control
                        type="text"
                        value={user.username}
                        disabled
                        className="bg-light"
                      />
                      <Form.Text className="text-muted">
                        Username cannot be changed
                      </Form.Text>
                    </Form.Group>

                    <Button 
                      type="submit" 
                      variant="primary"
                      disabled={loading}
                    >
                      {loading ? 'Updating...' : 'Update Profile'}
                    </Button>
                  </Form>
                </Card.Body>
              </Card>
            </Tab>

            <Tab eventKey="password" title="🔒 Change Password">
              <Card>
                <Card.Header>
                  <h5 className="mb-0">Change Password</h5>
                </Card.Header>
                <Card.Body>
                  <Form onSubmit={handlePasswordSubmit}>
                    <Form.Group className="mb-3">
                      <Form.Label>Current Password</Form.Label>
                      <Form.Control
                        type="password"
                        name="currentPassword"
                        value={passwordData.currentPassword}
                        onChange={handlePasswordChange}
                        required
                      />
                    </Form.Group>

                    <Form.Group className="mb-3">
                      <Form.Label>New Password</Form.Label>
                      <Form.Control
                        type="password"
                        name="newPassword"
                        value={passwordData.newPassword}
                        onChange={handlePasswordChange}
                        required
                        minLength={8}
                      />
                      <Form.Text className="text-muted">
                        Password must be at least 8 characters long
                      </Form.Text>
                    </Form.Group>

                    <Form.Group className="mb-3">
                      <Form.Label>Confirm New Password</Form.Label>
                      <Form.Control
                        type="password"
                        name="confirmPassword"
                        value={passwordData.confirmPassword}
                        onChange={handlePasswordChange}
                        required
                      />
                    </Form.Group>

                    <Button 
                      type="submit" 
                      variant="primary"
                      disabled={loading}
                    >
                      {loading ? 'Changing...' : 'Change Password'}
                    </Button>
                  </Form>
                </Card.Body>
              </Card>
            </Tab>

            <Tab eventKey="security" title="🛡️ Security">
              <Card>
                <Card.Header>
                  <h5 className="mb-0">Security Settings</h5>
                </Card.Header>
                <Card.Body>
                  <div className="mb-4">
                    <h6>Two-Factor Authentication</h6>
                    <p className="text-muted">
                      Add an extra layer of security to your account
                    </p>
                    <Button variant="outline-primary">
                      Enable 2FA
                    </Button>
                  </div>

                  <div className="mb-4">
                    <h6>Active Sessions</h6>
                    <p className="text-muted">
                      Manage where you're currently signed in
                    </p>
                    <Button variant="outline-danger">
                      Sign out of all devices
                    </Button>
                  </div>

                  <div className="mb-4">
                    <h6>API Keys</h6>
                    <p className="text-muted">
                      Generate API keys for programmatic access
                    </p>
                    <Button variant="outline-secondary">
                      Manage API Keys
                    </Button>
                  </div>
                </Card.Body>
              </Card>
            </Tab>
          </Tabs>
        </Col>

        <Col lg={4}>
          <Card>
            <Card.Header>
              <h5 className="mb-0">Account Overview</h5>
            </Card.Header>
            <Card.Body>
              <div className="text-center mb-3">
                <div
                  className="bg-primary rounded-circle d-inline-flex align-items-center justify-content-center"
                  style={{ width: '80px', height: '80px', fontSize: '2rem', color: 'white' }}
                >
                  {user.firstName.charAt(0)}{user.lastName.charAt(0)}
                </div>
              </div>

              <div className="text-center mb-3">
                <h5>{user.firstName} {user.lastName}</h5>
                <p className="text-muted">{user.email}</p>
              </div>

              <hr />

              <div className="mb-2">
                <strong>User ID:</strong> {user.id.slice(0, 8)}...
              </div>
              <div className="mb-2">
                <strong>Account Created:</strong> {new Date(user.createdAt).toLocaleDateString()}
              </div>
              <div className="mb-2">
                <strong>Last Login:</strong> {user.lastLogin ? new Date(user.lastLogin).toLocaleDateString() : 'Never'}
              </div>
              <div className="mb-2">
                <strong>Roles:</strong>
                <div className="mt-1">
                  {user.roles.map(role => (
                    <span key={role} className="badge bg-secondary me-1">
                      {role}
                    </span>
                  ))}
                </div>
              </div>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
} 