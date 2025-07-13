# Getting Started with KubeNexus

This guide will help you get KubeNexus up and running quickly.

## Prerequisites

Before deploying KubeNexus, ensure you have:

### Infrastructure Requirements

- **Kubernetes Cluster**: Version 1.24 or higher
- **Nodes**: Minimum 3 nodes (recommended for production)
- **Resources per Node**:
  - 8GB RAM minimum (16GB recommended)
  - 4 CPU cores minimum
  - 50GB disk space
- **Storage**: Support for persistent volumes
- **Network**: Load balancer support for ingress

### Required Tools

- **kubectl**: Kubernetes command-line tool
- **kustomize**: Kubernetes configuration management
- **Docker**: For building images (optional)
- **Helm**: Package manager for Kubernetes (optional)

### Access Requirements

- **Cluster Admin**: Access to deploy cluster-wide resources
- **Registry Access**: Docker registry for container images
- **DNS Management**: Ability to configure DNS records

## Quick Installation

### 1. Download KubeNexus

```bash
# Clone the repository
git clone https://github.com/your-org/kubenexus.git
cd kubenexus

# Or download and extract the release
curl -L https://github.com/your-org/kubenexus/archive/v1.0.0.tar.gz | tar xz
cd kubenexus-1.0.0
```

### 2. Configure Your Environment

Set up environment variables for your deployment:

```bash
# Domain configuration
export DOMAIN="kubenexus.yourdomain.com"
export API_DOMAIN="api.kubenexus.yourdomain.com"

# Registry configuration (if using custom registry)
export REGISTRY="your-registry.com/kubenexus"
export TAG="v1.0.0"
```

### 3. Update Secrets

Before deployment, update the secrets in `k8s/secrets.yaml`:

```bash
# Generate secure passwords
POSTGRES_PASSWORD=$(openssl rand -base64 32)
REDIS_PASSWORD=$(openssl rand -base64 32)
JWT_SECRET=$(openssl rand -base64 64)
ENCRYPTION_KEY=$(openssl rand -base64 32)

# Encode to base64
echo -n "$POSTGRES_PASSWORD" | base64
echo -n "$REDIS_PASSWORD" | base64
echo -n "$JWT_SECRET" | base64
echo -n "$ENCRYPTION_KEY" | base64
```

Replace the placeholder values in `k8s/secrets.yaml` with your base64-encoded secrets.

### 4. Deploy KubeNexus

Use the deployment script for easy installation:

```bash
# Deploy with custom domain
./scripts/deploy-k8s.sh --domain $DOMAIN

# Or deploy with defaults (requires manual DNS setup)
./scripts/deploy-k8s.sh
```

The deployment script will:
- Validate prerequisites
- Install NGINX Ingress Controller (if needed)
- Install cert-manager for SSL certificates
- Deploy all KubeNexus components
- Configure ingress and certificates

### 5. Verify Deployment

Check that all components are running:

```bash
# Check pods status
kubectl get pods -n kubenexus

# Check services
kubectl get services -n kubenexus

# Check ingress
kubectl get ingress -n kubenexus

# View deployment logs
kubectl logs -f deployment/api-gateway -n kubenexus
```

### 6. Configure DNS

Point your domain to the ingress external IP:

```bash
# Get external IP
kubectl get ingress kubenexus-ingress -n kubenexus

# Add DNS records
kubenexus.yourdomain.com     A    <EXTERNAL_IP>
api.kubenexus.yourdomain.com A    <EXTERNAL_IP>
```

## First Access

### 1. Access the Platform

Open your browser and navigate to:
- **Frontend**: `https://kubenexus.yourdomain.com`
- **API**: `https://api.kubenexus.yourdomain.com`

### 2. Initial Login

Use the default administrator credentials:
- **Username**: `admin`
- **Password**: `admin123!`

> ⚠️ **Important**: Change the default password immediately after first login!

### 3. Complete Setup Wizard

The setup wizard will guide you through:
1. Changing the admin password
2. Configuring basic settings
3. Adding your first cluster
4. Setting up monitoring

## Adding Your First Cluster

### 1. Prepare Cluster Access

Ensure you have:
- Kubeconfig file for the target cluster
- Appropriate RBAC permissions
- Network connectivity from KubeNexus to the cluster

### 2. Add Cluster via Web Interface

1. Navigate to **Clusters** → **Add Cluster**
2. Provide cluster details:
   - **Name**: Descriptive name for the cluster
   - **Description**: Optional description
   - **Provider**: Cloud provider (AWS, GCP, Azure, etc.)
   - **Region**: Cluster region
3. Upload or paste kubeconfig content
4. Test connection and save

### 3. Add Cluster via API

```bash
# Prepare kubeconfig (base64 encoded)
KUBECONFIG_B64=$(base64 -w 0 < path/to/kubeconfig)

# Create cluster via API
curl -X POST https://api.kubenexus.yourdomain.com/api/clusters \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "production-cluster",
    "description": "Production Kubernetes cluster",
    "provider": "aws",
    "region": "us-west-2",
    "kubeconfig": "'$KUBECONFIG_B64'"
  }'
```

## Enabling Monitoring

### 1. Configure Metrics Collection

KubeNexus automatically collects basic metrics, but you can enhance monitoring:

1. Navigate to **Monitoring** → **Configuration**
2. Enable advanced metrics collection
3. Configure alert rules
4. Set up notification channels

### 2. SRE Agent Setup

Enable the AI-powered SRE agent:

1. Go to **SRE** → **Configuration**
2. Enable anomaly detection
3. Configure analysis intervals
4. Set alert thresholds

## Next Steps

Now that KubeNexus is running:

### Learn the Platform
- Read the [User Guide](user-guide/) for detailed feature documentation
- Explore the [API Reference](api/) for programmatic access
- Check out [Examples](examples/) for common configurations

### Customize Your Setup
- Configure [authentication](user-guide/authentication.md) with your identity provider
- Set up [role-based access control](user-guide/authentication.md#rbac)
- Configure [monitoring and alerting](user-guide/monitoring.md)

### Production Considerations
- Review [security best practices](deployment/security.md)
- Set up [backup and disaster recovery](deployment/production.md#backup)
- Configure [high availability](deployment/production.md#high-availability)

## Troubleshooting

### Common Issues

**Pods not starting**:
```bash
# Check pod logs
kubectl logs -f deployment/auth-service -n kubenexus

# Check resource constraints
kubectl describe pod -l app=auth-service -n kubenexus
```

**Ingress not accessible**:
```bash
# Check ingress controller
kubectl get pods -n ingress-nginx

# Check ingress configuration
kubectl describe ingress kubenexus-ingress -n kubenexus
```

**Database connection issues**:
```bash
# Check PostgreSQL pod
kubectl get pods -l app=postgres -n kubenexus

# Check database connectivity
kubectl exec -it deployment/auth-service -n kubenexus -- nc -zv postgres-service 5432
```

### Getting Help

- Check the [Troubleshooting Guide](user-guide/troubleshooting.md)
- Review [Deployment Troubleshooting](deployment/troubleshooting.md)
- Search [GitHub Issues](https://github.com/your-org/kubenexus/issues)
- Join our community discussions

## What's Next?

- **[User Guide](user-guide/)**: Learn how to use all features
- **[Architecture](architecture.md)**: Understand the system design
- **[API Reference](api/)**: Integrate with KubeNexus programmatically
- **[Developer Guide](developer-guide/)**: Contribute to the project

---

**Need help?** Contact us at support@kubenexus.com or create an issue on GitHub. 