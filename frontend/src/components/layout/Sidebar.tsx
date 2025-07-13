import React from 'react';
import { Nav, Badge } from 'react-bootstrap';
import { useAuth } from '../../contexts/AuthContext';

interface SidebarProps {
  collapsed?: boolean;
}

export function Sidebar({ collapsed = false }: SidebarProps) {
  const { user } = useAuth();

  const menuItems = [
    { icon: 'speedometer2', label: 'Dashboard', path: '/dashboard' },
    { icon: 'diagram-3', label: 'Clusters', path: '/clusters' },
    { icon: 'graph-up', label: 'Monitoring', path: '/monitoring' },
    { icon: 'people', label: 'Users', path: '/users', roles: ['admin'] },
    { icon: 'shield-check', label: 'Audit Logs', path: '/audit-logs' },
    { icon: 'person-circle', label: 'Profile', path: '/profile' },
  ];

  const hasRole = (requiredRoles?: string[]) => {
    if (!requiredRoles) return true;
    if (!user?.role) return false;
    return requiredRoles.includes(user.role) || user.role === 'admin';
  };

  const filteredMenuItems = menuItems.filter(item => hasRole(item.roles));

  return (
    <div className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      <div className="sidebar-header">
        <h5 className="mb-0">
          <i className="bi bi-cloud me-2"></i>
          {!collapsed && 'KubeNexus'}
        </h5>
      </div>
      
      <Nav className="flex-column mt-3">
        {filteredMenuItems.map((item) => (
          <Nav.Link
            key={item.path}
            href={item.path}
            className="d-flex align-items-center py-3 px-4 text-decoration-none"
          >
            <i className={`bi bi-${item.icon} me-3`}></i>
            {!collapsed && (
              <span className="nav-text">{item.label}</span>
            )}
          </Nav.Link>
        ))}
      </Nav>
      
      {!collapsed && (
        <div className="sidebar-footer mt-auto p-3">
          <div className="user-info">
            <div className="d-flex align-items-center">
              <div className="avatar bg-primary rounded-circle me-3">
                {user?.username?.[0]?.toUpperCase()}
              </div>
              <div>
                <div className="small fw-medium">{user?.username}</div>
                <Badge bg="secondary" className="small">
                  {user?.role}
                </Badge>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
} 