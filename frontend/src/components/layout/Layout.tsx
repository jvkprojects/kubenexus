import React, { useState } from 'react';
import { Container } from 'react-bootstrap';
import { Sidebar } from './Sidebar';
import { TopNavbar } from './TopNavbar';

interface LayoutProps {
  children: React.ReactNode;
}

export const Layout: React.FC<LayoutProps> = ({ children }) => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const handleToggleSidebar = () => {
    setSidebarCollapsed(!sidebarCollapsed);
  };

  return (
    <div className="d-flex min-vh-100">
      <Sidebar collapsed={sidebarCollapsed} />
      <div className="flex-grow-1 d-flex flex-column">
        <TopNavbar onToggleSidebar={handleToggleSidebar} />
        <main className="flex-grow-1 p-4 bg-light">
          <Container fluid>
            {children}
          </Container>
        </main>
      </div>
    </div>
  );
}; 