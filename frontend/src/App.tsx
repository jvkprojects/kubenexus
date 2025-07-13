import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import { ProtectedRoute } from './components/auth/ProtectedRoute';
import { Layout } from './components/layout/Layout';
import { LoginPage } from './pages/auth/LoginPage';
import { Dashboard } from './pages/Dashboard';
import { ClustersPage } from './pages/clusters/ClustersPage';
import { ClusterDetails } from './pages/clusters/ClusterDetails';
import { MonitoringPage } from './pages/monitoring/MonitoringPage';
import { UsersPage } from './pages/users/UsersPage';
import { AuditLogsPage } from './pages/audit/AuditLogsPage';
import { ProfilePage } from './pages/profile/ProfilePage';
import 'bootstrap/dist/css/bootstrap.min.css';
import 'bootstrap-icons/font/bootstrap-icons.css';

function App() {
  return (
    <AuthProvider>
      <Routes>
        {/* Public Routes */}
        <Route path="/login" element={<LoginPage />} />
        
        {/* Protected Routes */}
        <Route 
          path="/*" 
          element={
            <ProtectedRoute>
              <Layout>
                <Routes>
                  <Route path="/" element={<Navigate to="/dashboard" replace />} />
                  <Route path="/dashboard" element={<Dashboard />} />
                  <Route path="/clusters" element={<ClustersPage />} />
                  <Route path="/clusters/:id" element={<ClusterDetails />} />
                  <Route path="/monitoring" element={<MonitoringPage />} />
                  <Route 
                    path="/users" 
                    element={
                      <ProtectedRoute requiredRoles={['admin']}>
                        <UsersPage />
                      </ProtectedRoute>
                    } 
                  />
                  <Route path="/audit-logs" element={<AuditLogsPage />} />
                  <Route path="/profile" element={<ProfilePage />} />
                  <Route path="*" element={<Navigate to="/dashboard" replace />} />
                </Routes>
              </Layout>
            </ProtectedRoute>
          } 
        />
      </Routes>
    </AuthProvider>
  );
}

export default App; 