-- KubeNexus Database Schema
-- Production-ready PostgreSQL schema for enterprise SaaS platform

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create custom types
CREATE TYPE cluster_type AS ENUM ('on-premise', 'eks', 'gke', 'aks');
CREATE TYPE cluster_status AS ENUM ('connected', 'disconnected', 'error', 'pending');
CREATE TYPE user_status AS ENUM ('active', 'inactive', 'suspended');
CREATE TYPE problem_severity AS ENUM ('critical', 'high', 'medium', 'low');
CREATE TYPE audit_action AS ENUM ('create', 'read', 'update', 'delete', 'login', 'logout', 'access_denied');

-- User Management Tables
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255), -- NULL for SSO/LDAP users
    sso_id VARCHAR(255), -- For SSO integration
    ldap_dn VARCHAR(500), -- For LDAP integration
    ad_dn VARCHAR(500), -- For Active Directory
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    status user_status DEFAULT 'active',
    last_login_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    is_system_role BOOLEAN DEFAULT FALSE, -- System roles cannot be deleted
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    resource_type VARCHAR(100), -- e.g., 'pods', 'deployments', 'clusters'
    action VARCHAR(50), -- e.g., 'list', 'create', 'update', 'delete'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    cluster_id UUID, -- NULL means global role, otherwise cluster-specific
    namespace VARCHAR(255), -- NULL means cluster-wide access
    granted_by UUID REFERENCES users(id),
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id, role_id, cluster_id, namespace)
);

CREATE TABLE role_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    UNIQUE(role_id, permission_id)
);

-- Cluster Management Tables
CREATE TABLE kubernetes_clusters (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) UNIQUE NOT NULL,
    type cluster_type NOT NULL,
    description TEXT,
    kubeconfig TEXT, -- Encrypted kubeconfig for on-premise clusters
    cloud_provider_config JSONB, -- Encrypted cloud provider configuration
    api_endpoint VARCHAR(500),
    status cluster_status DEFAULT 'pending',
    version VARCHAR(50), -- Kubernetes version
    node_count INTEGER DEFAULT 0,
    last_health_check TIMESTAMP WITH TIME ZONE,
    health_check_error TEXT,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Add foreign key reference after clusters table is created
ALTER TABLE user_roles ADD CONSTRAINT fk_user_roles_cluster 
    FOREIGN KEY (cluster_id) REFERENCES kubernetes_clusters(id) ON DELETE CASCADE;

-- Audit Logs Table
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action audit_action NOT NULL,
    resource_type VARCHAR(100),
    resource_name VARCHAR(255),
    resource_id UUID,
    namespace VARCHAR(255),
    cluster_id UUID REFERENCES kubernetes_clusters(id) ON DELETE SET NULL,
    ip_address INET,
    user_agent TEXT,
    request_data JSONB, -- Request payload
    response_data JSONB, -- Response data
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Application Settings Table
CREATE TABLE application_settings (
    key VARCHAR(255) PRIMARY KEY,
    value JSONB NOT NULL,
    description TEXT,
    is_encrypted BOOLEAN DEFAULT FALSE,
    updated_by UUID REFERENCES users(id),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- User Preferences Table
CREATE TABLE user_preferences (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key VARCHAR(255) NOT NULL,
    value JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, key)
);

-- Plugin Management Tables
CREATE TABLE plugins (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) UNIQUE NOT NULL,
    version VARCHAR(50) NOT NULL,
    description TEXT,
    configuration JSONB,
    status VARCHAR(50) DEFAULT 'disabled', -- enabled, disabled, error
    installed_by UUID REFERENCES users(id),
    installed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- SRE Agent Tables
CREATE TABLE problem_applications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cluster_id UUID NOT NULL REFERENCES kubernetes_clusters(id) ON DELETE CASCADE,
    namespace VARCHAR(255) NOT NULL,
    resource_type VARCHAR(100) NOT NULL, -- Pod, Deployment, StatefulSet, etc.
    resource_name VARCHAR(255) NOT NULL,
    problem_type VARCHAR(100) NOT NULL, -- CrashLoopBackOff, OOMKilled, HighCPU, etc.
    problem_description TEXT NOT NULL,
    severity problem_severity NOT NULL,
    detection_data JSONB, -- Raw data used for detection
    root_cause TEXT,
    auto_resolved BOOLEAN DEFAULT FALSE,
    resolved_by UUID REFERENCES users(id), -- Manual resolution
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE,
    last_occurrence TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    occurrence_count INTEGER DEFAULT 1
);

CREATE TABLE resolution_suggestions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    problem_id UUID NOT NULL REFERENCES problem_applications(id) ON DELETE CASCADE,
    suggestion_text TEXT NOT NULL,
    command_example TEXT, -- Example kubectl command
    documentation_link VARCHAR(500),
    confidence_score DECIMAL(3,2) CHECK (confidence_score >= 0 AND confidence_score <= 1),
    priority INTEGER DEFAULT 1, -- Order of suggestions
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Session Management Table (for Redis backup)
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    refresh_token VARCHAR(255) UNIQUE,
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_accessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Metrics Cache Table (for frequently accessed metrics)
CREATE TABLE metrics_cache (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cluster_id UUID NOT NULL REFERENCES kubernetes_clusters(id) ON DELETE CASCADE,
    metric_type VARCHAR(100) NOT NULL, -- cpu, memory, pod_count, etc.
    metric_data JSONB NOT NULL,
    namespace VARCHAR(255), -- NULL for cluster-level metrics
    cached_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    UNIQUE(cluster_id, metric_type, namespace)
);

-- Create indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_sso_id ON users(sso_id) WHERE sso_id IS NOT NULL;

CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_cluster_id ON user_roles(cluster_id);
CREATE INDEX idx_user_roles_expires_at ON user_roles(expires_at) WHERE expires_at IS NOT NULL;

CREATE INDEX idx_clusters_status ON kubernetes_clusters(status);
CREATE INDEX idx_clusters_type ON kubernetes_clusters(type);
CREATE INDEX idx_clusters_created_by ON kubernetes_clusters(created_by);

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_cluster_id ON audit_logs(cluster_id);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_resource_type ON audit_logs(resource_type);

CREATE INDEX idx_problem_applications_cluster_id ON problem_applications(cluster_id);
CREATE INDEX idx_problem_applications_severity ON problem_applications(severity);
CREATE INDEX idx_problem_applications_detected_at ON problem_applications(detected_at);
CREATE INDEX idx_problem_applications_resolved_at ON problem_applications(resolved_at);
CREATE INDEX idx_problem_applications_namespace ON problem_applications(namespace);

CREATE INDEX idx_resolution_suggestions_problem_id ON resolution_suggestions(problem_id);
CREATE INDEX idx_resolution_suggestions_confidence ON resolution_suggestions(confidence_score DESC);

CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_expires_at ON user_sessions(expires_at);
CREATE INDEX idx_user_sessions_session_token ON user_sessions(session_token);

CREATE INDEX idx_metrics_cache_cluster_id ON metrics_cache(cluster_id);
CREATE INDEX idx_metrics_cache_expires_at ON metrics_cache(expires_at);
CREATE INDEX idx_metrics_cache_type ON metrics_cache(metric_type);

-- Insert default system roles
INSERT INTO roles (id, name, description, is_system_role) VALUES
    (uuid_generate_v4(), 'admin', 'Full administrative access to all clusters and resources', TRUE),
    (uuid_generate_v4(), 'cluster-admin', 'Full access to a specific cluster', TRUE),
    (uuid_generate_v4(), 'cluster-viewer', 'Read-only access to cluster resources', TRUE),
    (uuid_generate_v4(), 'namespace-admin', 'Full access to a specific namespace', TRUE),
    (uuid_generate_v4(), 'namespace-editor', 'Edit access to a specific namespace (no delete)', TRUE),
    (uuid_generate_v4(), 'namespace-viewer', 'Read-only access to a specific namespace', TRUE),
    (uuid_generate_v4(), 'sre-engineer', 'Access to SRE features and problem resolution', TRUE);

-- Insert default permissions
INSERT INTO permissions (name, description, resource_type, action) VALUES
    -- Cluster permissions
    ('clusters.list', 'List all clusters', 'clusters', 'list'),
    ('clusters.create', 'Create new clusters', 'clusters', 'create'),
    ('clusters.update', 'Update cluster configurations', 'clusters', 'update'),
    ('clusters.delete', 'Delete clusters', 'clusters', 'delete'),
    ('clusters.health', 'View cluster health status', 'clusters', 'read'),
    
    -- Pod permissions
    ('pods.list', 'List pods', 'pods', 'list'),
    ('pods.create', 'Create pods', 'pods', 'create'),
    ('pods.update', 'Update pods', 'pods', 'update'),
    ('pods.delete', 'Delete pods', 'pods', 'delete'),
    ('pods.logs', 'View pod logs', 'pods', 'read'),
    ('pods.exec', 'Execute commands in pods', 'pods', 'exec'),
    
    -- Deployment permissions
    ('deployments.list', 'List deployments', 'deployments', 'list'),
    ('deployments.create', 'Create deployments', 'deployments', 'create'),
    ('deployments.update', 'Update deployments', 'deployments', 'update'),
    ('deployments.delete', 'Delete deployments', 'deployments', 'delete'),
    ('deployments.scale', 'Scale deployments', 'deployments', 'update'),
    
    -- Service permissions
    ('services.list', 'List services', 'services', 'list'),
    ('services.create', 'Create services', 'services', 'create'),
    ('services.update', 'Update services', 'services', 'update'),
    ('services.delete', 'Delete services', 'services', 'delete'),
    
    -- Node permissions
    ('nodes.list', 'List nodes', 'nodes', 'list'),
    ('nodes.update', 'Update nodes (drain, cordon)', 'nodes', 'update'),
    
    -- Namespace permissions
    ('namespaces.list', 'List namespaces', 'namespaces', 'list'),
    ('namespaces.create', 'Create namespaces', 'namespaces', 'create'),
    ('namespaces.update', 'Update namespaces', 'namespaces', 'update'),
    ('namespaces.delete', 'Delete namespaces', 'namespaces', 'delete'),
    
    -- SRE permissions
    ('sre.problems.list', 'List SRE problems', 'sre-problems', 'list'),
    ('sre.problems.resolve', 'Resolve SRE problems', 'sre-problems', 'update'),
    ('sre.suggestions.view', 'View resolution suggestions', 'sre-suggestions', 'read'),
    
    -- User management permissions
    ('users.list', 'List users', 'users', 'list'),
    ('users.create', 'Create users', 'users', 'create'),
    ('users.update', 'Update users', 'users', 'update'),
    ('users.delete', 'Delete users', 'users', 'delete'),
    ('roles.manage', 'Manage user roles', 'roles', 'update'),
    
    -- Audit permissions
    ('audit.logs.view', 'View audit logs', 'audit-logs', 'read');

-- Create default admin user (password: admin123!)
-- In production, this should be changed immediately
INSERT INTO users (id, username, email, password_hash, first_name, last_name, status) VALUES
    (uuid_generate_v4(), 'admin', 'admin@kubenexus.local', 
     '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', -- admin123!
     'System', 'Administrator', 'active');

-- Assign admin role to default admin user
INSERT INTO user_roles (user_id, role_id, granted_by)
SELECT u.id, r.id, u.id
FROM users u, roles r
WHERE u.username = 'admin' AND r.name = 'admin';

-- Insert default application settings
INSERT INTO application_settings (key, value, description) VALUES
    ('platform.name', '"KubeNexus"', 'Platform display name'),
    ('platform.version', '"1.0.0"', 'Current platform version'),
    ('security.session_timeout', '3600', 'Session timeout in seconds'),
    ('security.max_login_attempts', '5', 'Maximum failed login attempts'),
    ('security.lockout_duration', '900', 'Account lockout duration in seconds'),
    ('sre.monitoring_enabled', 'true', 'Enable SRE monitoring'),
    ('sre.monitoring_interval', '60', 'SRE monitoring interval in seconds'),
    ('metrics.retention_days', '30', 'Metrics data retention period'),
    ('audit.retention_days', '90', 'Audit log retention period');

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at columns
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_clusters_updated_at BEFORE UPDATE ON kubernetes_clusters
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_plugins_updated_at BEFORE UPDATE ON plugins
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_preferences_updated_at BEFORE UPDATE ON user_preferences
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_application_settings_updated_at BEFORE UPDATE ON application_settings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Create function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM user_sessions WHERE expires_at < CURRENT_TIMESTAMP;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Create function to clean up expired metrics cache
CREATE OR REPLACE FUNCTION cleanup_expired_metrics()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM metrics_cache WHERE expires_at < CURRENT_TIMESTAMP;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions to application user (will be created by the application)
-- These will be applied when the application user is created
COMMENT ON DATABASE kubenexus IS 'KubeNexus Enterprise SaaS Platform Database';

-- =============================================================================
-- COMPREHENSIVE SEED DATA FOR DEVELOPMENT/DEMO
-- =============================================================================

-- Insert sample users with different roles
INSERT INTO users (id, username, email, password_hash, first_name, last_name, status, created_at, last_login_at) VALUES
    -- Additional admin user
    (uuid_generate_v4(), 'john.doe', 'john.doe@kubenexus.local', 
     '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/hZD8UjF8MBP.lbZhG', 
     'John', 'Doe', 'active', NOW() - INTERVAL '30 days', NOW() - INTERVAL '2 hours'),
    
    -- Cluster admin user
    (uuid_generate_v4(), 'sarah.wilson', 'sarah.wilson@kubenexus.local', 
     '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/hZD8UjF8MBP.lbZhG', 
     'Sarah', 'Wilson', 'active', NOW() - INTERVAL '20 days', NOW() - INTERVAL '1 hour'),
    
    -- SRE engineer
    (uuid_generate_v4(), 'mike.chen', 'mike.chen@kubenexus.local', 
     '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/hZD8UjF8MBP.lbZhG', 
     'Mike', 'Chen', 'active', NOW() - INTERVAL '15 days', NOW() - INTERVAL '30 minutes'),
    
    -- Namespace viewer
    (uuid_generate_v4(), 'emma.davis', 'emma.davis@kubenexus.local', 
     '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/hZD8UjF8MBP.lbZhG', 
     'Emma', 'Davis', 'active', NOW() - INTERVAL '10 days', NOW() - INTERVAL '15 minutes'),
    
    -- Inactive user
    (uuid_generate_v4(), 'alex.taylor', 'alex.taylor@kubenexus.local', 
     '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/hZD8UjF8MBP.lbZhG', 
     'Alex', 'Taylor', 'inactive', NOW() - INTERVAL '60 days', NOW() - INTERVAL '30 days');

-- Insert sample clusters
INSERT INTO kubernetes_clusters (id, name, type, description, api_endpoint, status, version, node_count, created_by, created_at, updated_at, last_health_check) VALUES
    (uuid_generate_v4(), 'production-us-east-1', 'eks', 'Production EKS cluster in US East 1', 
     'https://5F4C8B2A1E3D4F5B6C7D8E9F0A1B2C3D.gr7.us-east-1.eks.amazonaws.com', 
     'connected', '1.28.3', 5, 
     (SELECT id FROM users WHERE username = 'admin'), 
     NOW() - INTERVAL '60 days', NOW() - INTERVAL '5 minutes', NOW() - INTERVAL '2 minutes'),
    
    (uuid_generate_v4(), 'staging-us-west-2', 'eks', 'Staging EKS cluster in US West 2', 
     'https://2A3B4C5D6E7F8G9H0I1J2K3L4M5N6O7P.yl4.us-west-2.eks.amazonaws.com', 
     'connected', '1.28.1', 3, 
     (SELECT id FROM users WHERE username = 'sarah.wilson'), 
     NOW() - INTERVAL '45 days', NOW() - INTERVAL '10 minutes', NOW() - INTERVAL '1 minute'),
    
    (uuid_generate_v4(), 'gke-production-europe', 'gke', 'Production GKE cluster in Europe', 
     'https://k8s-cluster-prod-europe-4f2a1b3c.gcp.example.com', 
     'connected', '1.28.2', 4, 
     (SELECT id FROM users WHERE username = 'john.doe'), 
     NOW() - INTERVAL '30 days', NOW() - INTERVAL '3 minutes', NOW() - INTERVAL '30 seconds'),
    
    (uuid_generate_v4(), 'aks-dev-northeurope', 'aks', 'Development AKS cluster in North Europe', 
     'https://kubenexus-dev-northeurope-dns-5f4c8b2a.hcp.northeurope.azmk8s.io', 
     'connected', '1.27.7', 2, 
     (SELECT id FROM users WHERE username = 'mike.chen'), 
     NOW() - INTERVAL '25 days', NOW() - INTERVAL '7 minutes', NOW() - INTERVAL '45 seconds'),
    
    (uuid_generate_v4(), 'onprem-datacenter-1', 'on-premise', 'On-premise cluster in datacenter 1', 
     'https://k8s-master-01.datacenter1.company.com:6443', 
     'connected', '1.28.0', 6, 
     (SELECT id FROM users WHERE username = 'admin'), 
     NOW() - INTERVAL '90 days', NOW() - INTERVAL '15 minutes', NOW() - INTERVAL '1 minute'),
    
    (uuid_generate_v4(), 'test-cluster-failed', 'eks', 'Test cluster with connection issues', 
     'https://1G2H3I4J5K6L7M8N9O0P1Q2R3S4T5U6V.sk8.us-east-1.eks.amazonaws.com', 
     'error', '1.27.8', 0, 
     (SELECT id FROM users WHERE username = 'emma.davis'), 
     NOW() - INTERVAL '5 days', NOW() - INTERVAL '2 hours', NOW() - INTERVAL '2 hours');

-- Assign roles to users
INSERT INTO user_roles (user_id, role_id, granted_by) VALUES
    -- John Doe - admin role
    ((SELECT id FROM users WHERE username = 'john.doe'), 
     (SELECT id FROM roles WHERE name = 'admin'), 
     (SELECT id FROM users WHERE username = 'admin')),
    
    -- Sarah Wilson - cluster-admin role
    ((SELECT id FROM users WHERE username = 'sarah.wilson'), 
     (SELECT id FROM roles WHERE name = 'cluster-admin'), 
     (SELECT id FROM users WHERE username = 'admin')),
    
    -- Mike Chen - sre-engineer role
    ((SELECT id FROM users WHERE username = 'mike.chen'), 
     (SELECT id FROM roles WHERE name = 'sre-engineer'), 
     (SELECT id FROM users WHERE username = 'admin')),
    
    -- Emma Davis - namespace-viewer role
    ((SELECT id FROM users WHERE username = 'emma.davis'), 
     (SELECT id FROM roles WHERE name = 'namespace-viewer'), 
     (SELECT id FROM users WHERE username = 'admin'));

-- Insert sample audit logs
INSERT INTO audit_logs (id, user_id, action, resource_type, resource_name, resource_id, namespace, cluster_id, ip_address, success, timestamp) VALUES
    (uuid_generate_v4(), (SELECT id FROM users WHERE username = 'admin'), 'login', 'user', 'admin', 
     (SELECT id FROM users WHERE username = 'admin'), NULL, NULL, '192.168.1.100', true, NOW() - INTERVAL '2 hours'),
    
    (uuid_generate_v4(), (SELECT id FROM users WHERE username = 'john.doe'), 'create', 'cluster', 'gke-production-europe', 
     (SELECT id FROM kubernetes_clusters WHERE name = 'gke-production-europe'), NULL, 
     (SELECT id FROM kubernetes_clusters WHERE name = 'gke-production-europe'), '10.0.1.50', true, NOW() - INTERVAL '30 days'),
    
    (uuid_generate_v4(), (SELECT id FROM users WHERE username = 'sarah.wilson'), 'create', 'deployment', 'nginx-deployment', 
     NULL, 'default', (SELECT id FROM kubernetes_clusters WHERE name = 'staging-us-west-2'), '10.0.2.25', true, NOW() - INTERVAL '3 hours'),
    
    (uuid_generate_v4(), (SELECT id FROM users WHERE username = 'mike.chen'), 'read', 'pod', 'nginx-pod-12345', 
     NULL, 'production', (SELECT id FROM kubernetes_clusters WHERE name = 'production-us-east-1'), '10.0.3.75', true, NOW() - INTERVAL '1 hour'),
    
    (uuid_generate_v4(), (SELECT id FROM users WHERE username = 'emma.davis'), 'access_denied', 'deployment', 'critical-app', 
     NULL, 'production', (SELECT id FROM kubernetes_clusters WHERE name = 'production-us-east-1'), '10.0.4.100', false, NOW() - INTERVAL '45 minutes'),
    
    (uuid_generate_v4(), (SELECT id FROM users WHERE username = 'sarah.wilson'), 'update', 'service', 'web-service', 
     NULL, 'staging', (SELECT id FROM kubernetes_clusters WHERE name = 'staging-us-west-2'), '10.0.2.30', true, NOW() - INTERVAL '30 minutes'),
    
    (uuid_generate_v4(), (SELECT id FROM users WHERE username = 'admin'), 'delete', 'namespace', 'old-namespace', 
     NULL, 'old-namespace', (SELECT id FROM kubernetes_clusters WHERE name = 'onprem-datacenter-1'), '192.168.1.100', true, NOW() - INTERVAL '6 hours'),
    
    (uuid_generate_v4(), (SELECT id FROM users WHERE username = 'mike.chen'), 'create', 'user', 'emma.davis', 
     (SELECT id FROM users WHERE username = 'emma.davis'), NULL, NULL, '10.0.3.80', true, NOW() - INTERVAL '10 days');

-- Insert sample SRE problems
INSERT INTO problem_applications (id, cluster_id, namespace, resource_type, resource_name, problem_type, problem_description, severity, detection_data, root_cause, detected_at, last_occurrence, occurrence_count) VALUES
    (uuid_generate_v4(), (SELECT id FROM kubernetes_clusters WHERE name = 'production-us-east-1'), 'default', 'Pod', 'web-app-7d4b5c6789-xyz12', 'CrashLoopBackOff', 
     'Pod is in CrashLoopBackOff state due to application startup failure', 'high', 
     '{"exit_code": 1, "restart_count": 15, "last_restart": "2024-01-15T10:30:00Z"}', 
     'Missing environment variable DATABASE_URL causing application to fail during startup', 
     NOW() - INTERVAL '2 hours', NOW() - INTERVAL '5 minutes', 15),
    
    (uuid_generate_v4(), (SELECT id FROM kubernetes_clusters WHERE name = 'staging-us-west-2'), 'production', 'Pod', 'api-server-6c8d9e0f12-abc34', 'OOMKilled', 
     'Pod terminated due to out of memory condition', 'critical', 
     '{"memory_usage": "512Mi", "memory_limit": "256Mi", "killed_at": "2024-01-15T09:15:00Z"}', 
     'Memory limit too low for application requirements, causing OOM kills', 
     NOW() - INTERVAL '3 hours', NOW() - INTERVAL '10 minutes', 3),
    
    (uuid_generate_v4(), (SELECT id FROM kubernetes_clusters WHERE name = 'gke-production-europe'), 'monitoring', 'Deployment', 'prometheus-server', 'HighCPUUsage', 
     'Deployment showing consistently high CPU usage above 80%', 'medium', 
     '{"cpu_usage": "850m", "cpu_limit": "1000m", "duration": "45m"}', 
     'Increased load due to new metrics collection rules', 
     NOW() - INTERVAL '1 hour', NOW() - INTERVAL '2 minutes', 1),
    
    (uuid_generate_v4(), (SELECT id FROM kubernetes_clusters WHERE name = 'aks-dev-northeurope'), 'default', 'Service', 'database-service', 'ServiceUnavailable', 
     'Service endpoints are not available, causing connection failures', 'high', 
     '{"endpoint_count": 0, "selector": "app=database", "last_check": "2024-01-15T11:00:00Z"}', 
     'Database pods are not running due to persistent volume claim issues', 
     NOW() - INTERVAL '30 minutes', NOW() - INTERVAL '1 minute', 8),
    
    (uuid_generate_v4(), (SELECT id FROM kubernetes_clusters WHERE name = 'onprem-datacenter-1'), 'kube-system', 'Node', 'worker-node-03', 'NodeNotReady', 
     'Node is in NotReady state and not accepting new pods', 'critical', 
     '{"node_status": "NotReady", "last_heartbeat": "2024-01-15T10:45:00Z", "reason": "NetworkUnavailable"}', 
     'Network connectivity issues preventing kubelet from communicating with control plane', 
     NOW() - INTERVAL '15 minutes', NOW() - INTERVAL '30 seconds', 1);

-- Insert resolution suggestions for problems
INSERT INTO resolution_suggestions (id, problem_id, suggestion_text, command_example, documentation_link, confidence_score, priority) VALUES
    ((SELECT uuid_generate_v4()), (SELECT id FROM problem_applications WHERE resource_name = 'web-app-7d4b5c6789-xyz12'), 
     'Add the missing DATABASE_URL environment variable to the deployment configuration', 
     'kubectl set env deployment/web-app DATABASE_URL=postgresql://user:pass@db:5432/mydb', 
     'https://kubernetes.io/docs/tasks/inject-data-application/define-environment-variable-container/', 
     0.95, 1),
    
    ((SELECT uuid_generate_v4()), (SELECT id FROM problem_applications WHERE resource_name = 'web-app-7d4b5c6789-xyz12'), 
     'Check application logs for detailed error messages', 
     'kubectl logs deployment/web-app --previous', 
     'https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands#logs', 
     0.85, 2),
    
    ((SELECT uuid_generate_v4()), (SELECT id FROM problem_applications WHERE resource_name = 'api-server-6c8d9e0f12-abc34'), 
     'Increase memory limits for the pod to prevent OOM kills', 
     'kubectl patch deployment api-server -p ''{"spec":{"template":{"spec":{"containers":[{"name":"api-server","resources":{"limits":{"memory":"1Gi"}}}]}}}}''', 
     'https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/', 
     0.90, 1),
    
    ((SELECT uuid_generate_v4()), (SELECT id FROM problem_applications WHERE resource_name = 'api-server-6c8d9e0f12-abc34'), 
     'Review application memory usage patterns and optimize if possible', 
     'kubectl top pods -n production', 
     'https://kubernetes.io/docs/tasks/debug-application-cluster/resource-usage-monitoring/', 
     0.75, 2),
    
    ((SELECT uuid_generate_v4()), (SELECT id FROM problem_applications WHERE resource_name = 'prometheus-server'), 
     'Add horizontal pod autoscaler to handle increased load', 
     'kubectl autoscale deployment prometheus-server --cpu-percent=70 --min=1 --max=3', 
     'https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/', 
     0.80, 1),
    
    ((SELECT uuid_generate_v4()), (SELECT id FROM problem_applications WHERE resource_name = 'database-service'), 
     'Check if database pods are running and healthy', 
     'kubectl get pods -l app=database -o wide', 
     'https://kubernetes.io/docs/concepts/workloads/pods/', 
     0.85, 1),
    
    ((SELECT uuid_generate_v4()), (SELECT id FROM problem_applications WHERE resource_name = 'database-service'), 
     'Verify persistent volume claims are bound correctly', 
     'kubectl get pvc -n default', 
     'https://kubernetes.io/docs/concepts/storage/persistent-volumes/', 
     0.90, 2),
    
    ((SELECT uuid_generate_v4()), (SELECT id FROM problem_applications WHERE resource_name = 'worker-node-03'), 
     'Check node network connectivity and restart network services', 
     'kubectl describe node worker-node-03', 
     'https://kubernetes.io/docs/tasks/debug-application-cluster/debug-cluster/', 
     0.85, 1),
    
    ((SELECT uuid_generate_v4()), (SELECT id FROM problem_applications WHERE resource_name = 'worker-node-03'), 
     'Cordon the node and drain workloads if network issues persist', 
     'kubectl cordon worker-node-03 && kubectl drain worker-node-03 --ignore-daemonsets', 
     'https://kubernetes.io/docs/tasks/administer-cluster/safely-drain-node/', 
     0.70, 2);

-- Insert sample metrics cache data
INSERT INTO metrics_cache (id, cluster_id, metric_type, metric_data, namespace, cached_at, expires_at) VALUES
    (uuid_generate_v4(), (SELECT id FROM kubernetes_clusters WHERE name = 'production-us-east-1'), 'cpu_usage', 
     '{"value": 65.4, "timestamp": "2024-01-15T12:00:00Z", "unit": "percent"}', 
     NULL, NOW() - INTERVAL '5 minutes', NOW() + INTERVAL '25 minutes'),
    
    (uuid_generate_v4(), (SELECT id FROM kubernetes_clusters WHERE name = 'production-us-east-1'), 'memory_usage', 
     '{"value": 78.2, "timestamp": "2024-01-15T12:00:00Z", "unit": "percent"}', 
     NULL, NOW() - INTERVAL '5 minutes', NOW() + INTERVAL '25 minutes'),
    
    (uuid_generate_v4(), (SELECT id FROM kubernetes_clusters WHERE name = 'staging-us-west-2'), 'cpu_usage', 
     '{"value": 42.1, "timestamp": "2024-01-15T12:00:00Z", "unit": "percent"}', 
     NULL, NOW() - INTERVAL '3 minutes', NOW() + INTERVAL '27 minutes'),
    
    (uuid_generate_v4(), (SELECT id FROM kubernetes_clusters WHERE name = 'gke-production-europe'), 'pod_count', 
     '{"total_pods": 45, "running_pods": 42, "failed_pods": 2, "pending_pods": 1}', 
     NULL, NOW() - INTERVAL '2 minutes', NOW() + INTERVAL '28 minutes'),
    
    (uuid_generate_v4(), (SELECT id FROM kubernetes_clusters WHERE name = 'aks-dev-northeurope'), 'node_count', 
     '{"total_nodes": 2, "ready_nodes": 2, "not_ready_nodes": 0}', 
     NULL, NOW() - INTERVAL '1 minute', NOW() + INTERVAL '29 minutes');

-- Insert sample application settings for demo
INSERT INTO application_settings (key, value, description, updated_by) VALUES
    ('demo.sample_data_loaded', 'true', 'Indicates that sample data has been loaded for demo purposes', 
     (SELECT id FROM users WHERE username = 'admin')),
    ('dashboard.refresh_interval', '30', 'Dashboard auto-refresh interval in seconds', 
     (SELECT id FROM users WHERE username = 'admin')),
    ('sre.alert_threshold_cpu', '80', 'CPU usage threshold for SRE alerts', 
     (SELECT id FROM users WHERE username = 'mike.chen')),
    ('sre.alert_threshold_memory', '85', 'Memory usage threshold for SRE alerts', 
     (SELECT id FROM users WHERE username = 'mike.chen'));

-- Insert sample user preferences
INSERT INTO user_preferences (user_id, key, value) VALUES
    ((SELECT id FROM users WHERE username = 'admin'), 'dashboard.layout', '{"widgets": ["clusters", "alerts", "metrics"]}'),
    ((SELECT id FROM users WHERE username = 'john.doe'), 'theme', '{"mode": "dark", "primary_color": "#007bff"}'),
    ((SELECT id FROM users WHERE username = 'sarah.wilson'), 'notifications', '{"email": true, "browser": true, "sms": false}'),
    ((SELECT id FROM users WHERE username = 'mike.chen'), 'sre.monitoring_view', '{"default_severity": "high", "auto_refresh": true}'),
    ((SELECT id FROM users WHERE username = 'emma.davis'), 'cluster.default_namespace', '{"namespace": "default", "show_system": false}');

-- Create some sample plugins
INSERT INTO plugins (id, name, version, description, configuration, status, installed_by) VALUES
    (uuid_generate_v4(), 'prometheus-integration', '1.2.3', 'Prometheus metrics integration plugin', 
     '{"endpoint": "http://prometheus:9090", "scrape_interval": "30s"}', 'enabled', 
     (SELECT id FROM users WHERE username = 'admin')),
    
    (uuid_generate_v4(), 'grafana-dashboards', '2.1.0', 'Grafana dashboard integration', 
     '{"grafana_url": "http://grafana:3000", "api_key": "encrypted_key_here"}', 'enabled', 
     (SELECT id FROM users WHERE username = 'admin')),
    
    (uuid_generate_v4(), 'slack-notifications', '1.0.5', 'Slack notification plugin for alerts', 
     '{"webhook_url": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX", "channel": "#alerts"}', 'disabled', 
     (SELECT id FROM users WHERE username = 'mike.chen'));

-- Add role permissions mapping
INSERT INTO role_permissions (role_id, permission_id) VALUES
    -- Admin role gets all permissions
    ((SELECT id FROM roles WHERE name = 'admin'), (SELECT id FROM permissions WHERE name = 'clusters.list')),
    ((SELECT id FROM roles WHERE name = 'admin'), (SELECT id FROM permissions WHERE name = 'clusters.create')),
    ((SELECT id FROM roles WHERE name = 'admin'), (SELECT id FROM permissions WHERE name = 'clusters.update')),
    ((SELECT id FROM roles WHERE name = 'admin'), (SELECT id FROM permissions WHERE name = 'clusters.delete')),
    ((SELECT id FROM roles WHERE name = 'admin'), (SELECT id FROM permissions WHERE name = 'users.list')),
    ((SELECT id FROM roles WHERE name = 'admin'), (SELECT id FROM permissions WHERE name = 'users.create')),
    ((SELECT id FROM roles WHERE name = 'admin'), (SELECT id FROM permissions WHERE name = 'users.update')),
    ((SELECT id FROM roles WHERE name = 'admin'), (SELECT id FROM permissions WHERE name = 'users.delete')),
    ((SELECT id FROM roles WHERE name = 'admin'), (SELECT id FROM permissions WHERE name = 'audit.logs.view')),
    
    -- Cluster admin role permissions
    ((SELECT id FROM roles WHERE name = 'cluster-admin'), (SELECT id FROM permissions WHERE name = 'clusters.list')),
    ((SELECT id FROM roles WHERE name = 'cluster-admin'), (SELECT id FROM permissions WHERE name = 'clusters.create')),
    ((SELECT id FROM roles WHERE name = 'cluster-admin'), (SELECT id FROM permissions WHERE name = 'clusters.update')),
    ((SELECT id FROM roles WHERE name = 'cluster-admin'), (SELECT id FROM permissions WHERE name = 'pods.list')),
    ((SELECT id FROM roles WHERE name = 'cluster-admin'), (SELECT id FROM permissions WHERE name = 'pods.create')),
    ((SELECT id FROM roles WHERE name = 'cluster-admin'), (SELECT id FROM permissions WHERE name = 'pods.update')),
    ((SELECT id FROM roles WHERE name = 'cluster-admin'), (SELECT id FROM permissions WHERE name = 'pods.delete')),
    ((SELECT id FROM roles WHERE name = 'cluster-admin'), (SELECT id FROM permissions WHERE name = 'deployments.list')),
    ((SELECT id FROM roles WHERE name = 'cluster-admin'), (SELECT id FROM permissions WHERE name = 'deployments.create')),
    ((SELECT id FROM roles WHERE name = 'cluster-admin'), (SELECT id FROM permissions WHERE name = 'deployments.update')),
    ((SELECT id FROM roles WHERE name = 'cluster-admin'), (SELECT id FROM permissions WHERE name = 'deployments.delete')),
    
    -- SRE engineer role permissions
    ((SELECT id FROM roles WHERE name = 'sre-engineer'), (SELECT id FROM permissions WHERE name = 'clusters.list')),
    ((SELECT id FROM roles WHERE name = 'sre-engineer'), (SELECT id FROM permissions WHERE name = 'clusters.health')),
    ((SELECT id FROM roles WHERE name = 'sre-engineer'), (SELECT id FROM permissions WHERE name = 'pods.list')),
    ((SELECT id FROM roles WHERE name = 'sre-engineer'), (SELECT id FROM permissions WHERE name = 'pods.logs')),
    ((SELECT id FROM roles WHERE name = 'sre-engineer'), (SELECT id FROM permissions WHERE name = 'sre.problems.list')),
    ((SELECT id FROM roles WHERE name = 'sre-engineer'), (SELECT id FROM permissions WHERE name = 'sre.problems.resolve')),
    ((SELECT id FROM roles WHERE name = 'sre-engineer'), (SELECT id FROM permissions WHERE name = 'sre.suggestions.view')),
    
    -- Namespace viewer role permissions
    ((SELECT id FROM roles WHERE name = 'namespace-viewer'), (SELECT id FROM permissions WHERE name = 'clusters.list')),
    ((SELECT id FROM roles WHERE name = 'namespace-viewer'), (SELECT id FROM permissions WHERE name = 'pods.list')),
    ((SELECT id FROM roles WHERE name = 'namespace-viewer'), (SELECT id FROM permissions WHERE name = 'pods.logs')),
    ((SELECT id FROM roles WHERE name = 'namespace-viewer'), (SELECT id FROM permissions WHERE name = 'services.list')),
    ((SELECT id FROM roles WHERE name = 'namespace-viewer'), (SELECT id FROM permissions WHERE name = 'deployments.list'));

-- Add some sample user sessions for active users
INSERT INTO user_sessions (user_id, session_token, refresh_token, ip_address, user_agent, expires_at, created_at, last_accessed_at) VALUES
    ((SELECT id FROM users WHERE username = 'admin'), 
     'sess_admin_' || encode(gen_random_bytes(16), 'hex'), 
     'refresh_admin_' || encode(gen_random_bytes(16), 'hex'), 
     '192.168.1.100', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', 
     NOW() + INTERVAL '1 hour', NOW() - INTERVAL '2 hours', NOW() - INTERVAL '5 minutes'),
    
    ((SELECT id FROM users WHERE username = 'john.doe'), 
     'sess_john_' || encode(gen_random_bytes(16), 'hex'), 
     'refresh_john_' || encode(gen_random_bytes(16), 'hex'), 
     '10.0.1.50', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36', 
     NOW() + INTERVAL '45 minutes', NOW() - INTERVAL '1 hour', NOW() - INTERVAL '2 minutes'),
    
    ((SELECT id FROM users WHERE username = 'mike.chen'), 
     'sess_mike_' || encode(gen_random_bytes(16), 'hex'), 
     'refresh_mike_' || encode(gen_random_bytes(16), 'hex'), 
     '10.0.3.75', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36', 
     NOW() + INTERVAL '30 minutes', NOW() - INTERVAL '30 minutes', NOW() - INTERVAL '1 minute');

-- Final summary comment
COMMENT ON SCHEMA public IS 'KubeNexus database schema with comprehensive seed data for development and demonstration purposes'; 