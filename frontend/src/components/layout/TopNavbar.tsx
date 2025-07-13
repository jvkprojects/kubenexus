import React from 'react';
import { Navbar, Nav, Dropdown, Button } from 'react-bootstrap';
import { useAuth } from '../../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';

interface TopNavbarProps {
  onToggleSidebar: () => void;
}

export function TopNavbar({ onToggleSidebar }: TopNavbarProps) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <Navbar className="navbar-custom px-3" expand="lg">
      <div className="d-flex align-items-center w-100">
        <Button
          variant="outline-secondary"
          className="d-md-none me-3"
          onClick={onToggleSidebar}
        >
          ☰
        </Button>

        <div className="ms-auto">
          <Nav>
            <Dropdown align="end">
              <Dropdown.Toggle 
                variant="outline-secondary" 
                id="user-dropdown"
                className="border-0"
              >
                <span className="me-2">👤</span>
                {user?.firstName} {user?.lastName}
              </Dropdown.Toggle>

              <Dropdown.Menu>
                <Dropdown.Item onClick={() => navigate('/profile')}>
                  👤 Profile
                </Dropdown.Item>
                <Dropdown.Divider />
                <Dropdown.Item onClick={handleLogout}>
                  🚪 Logout
                </Dropdown.Item>
              </Dropdown.Menu>
            </Dropdown>
          </Nav>
        </div>
      </div>
    </Navbar>
  );
} 