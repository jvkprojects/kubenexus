# KubeNexus Deployment Scripts

This directory contains scripts to deploy, manage, and develop the KubeNexus platform on Kubernetes.

## Scripts Overview

### Production Deployment

- **`deploy-k8s.sh`** - Main deployment script for production environments
- **`build-images.sh`** - Build and push Docker images
- **`update-deployment.sh`** - Update existing deployments
- **`cleanup-k8s.sh`** - Clean up and remove deployments

### Development Environment

- **`setup-dev-environment.sh`** - Set up local development environment with minikube
- **`dev-deploy.sh`** - Quick development deployment (created by setup script)
- **`dev-cleanup.sh`** - Clean up development environment (created by setup script)

## Quick Start

### Production Deployment

1. **Build and push images:**
   ```bash
   ./scripts/build-images.sh --registry your-registry --tag v1.0.0
   ```

2. **Deploy to Kubernetes:**
   ```bash
   ./scripts/deploy-k8s.sh --domain your-domain.com
   ```

### Development Environment

1. **Set up development environment:**
   ```bash
   ./scripts/setup-dev-environment.sh
   ```

2. **Deploy for development:**
   ```bash
   ./scripts/dev-deploy.sh
   ```

## Detailed Usage

### deploy-k8s.sh

Main production deployment script with comprehensive features:

```bash
# Basic deployment
./scripts/deploy-k8s.sh

# Custom domain deployment
./scripts/deploy-k8s.sh --domain kubenexus.example.com

# Skip prerequisites (if already installed)
./scripts/deploy-k8s.sh --skip-prerequisites

# Dry run (see what would be deployed)
./scripts/deploy-k8s.sh --dry-run
```

**Features:**
- Validates prerequisites and environment
- Installs NGINX Ingress Controller and cert-manager
- Updates configurations with custom domains
- Validates secrets before deployment
- Waits for all deployments to be ready
- Provides deployment status and access information

**Prerequisites:**
- kubectl configured for target cluster
- kustomize installed
- Docker (for image building verification)

### build-images.sh

Builds and pushes all Docker images for the platform:

```bash
# Build all images
./scripts/build-images.sh

# Build with custom registry and tag
./scripts/build-images.sh --registry my-registry.com/kubenexus --tag v1.1.0

# Build in parallel for faster builds
./scripts/build-images.sh --parallel

# Build only specific service
./scripts/build-images.sh --service auth-service

# Build without pushing (local development)
./scripts/build-images.sh --no-push
```

**Features:**
- Builds all backend services and frontend
- Supports parallel building for performance
- Validates built images
- Cleans up old images
- Provides build summary

### update-deployment.sh

Updates existing deployments with new image versions:

```bash
# Update all services to new version
./scripts/update-deployment.sh --new-tag v1.1.0

# Update specific service
./scripts/update-deployment.sh --service auth-service --new-tag v1.1.0

# Rollback to previous version
./scripts/update-deployment.sh --rollback

# Check current versions
./scripts/update-deployment.sh --check-only
```

**Features:**
- Rolling updates with zero downtime
- Backup current state before updates
- Health checks after deployment
- Rollback capability
- Single service or full platform updates

### cleanup-k8s.sh

Safely removes KubeNexus deployment:

```bash
# Interactive cleanup with backup
./scripts/cleanup-k8s.sh

# Force cleanup without prompts
./scripts/cleanup-k8s.sh --force --no-backup

# Only delete RBAC resources
./scripts/cleanup-k8s.sh --rbac-only

# Verify what would be deleted
./scripts/cleanup-k8s.sh --verify-only
```

**Features:**
- Creates backup before deletion
- Interactive confirmation for safety
- Comprehensive cleanup of all resources
- Verification mode to preview actions
- Selective cleanup options

### setup-dev-environment.sh

Sets up complete local development environment:

```bash
# Full development setup
./scripts/setup-dev-environment.sh

# Custom memory allocation
./scripts/setup-dev-environment.sh --memory 16384

# Use existing cluster
./scripts/setup-dev-environment.sh --skip-minikube

# Skip local DNS setup
./scripts/setup-dev-environment.sh --skip-dns
```

**Features:**
- Installs all required tools (kubectl, minikube, kustomize, skaffold)
- Sets up minikube cluster with proper configuration
- Creates development namespace and configurations
- Sets up local DNS for easy access
- Creates helper scripts for development

## Environment Variables

All scripts support environment variables for configuration:

```bash
# Image configuration
export REGISTRY="your-registry.com/kubenexus"
export TAG="v1.0.0"

# Domain configuration
export DOMAIN="kubenexus.example.com"
export API_DOMAIN="api.kubenexus.example.com"

# Development configuration
export DEV_NAMESPACE="kubenexus-dev"
export MINIKUBE_PROFILE="kubenexus"

# Build configuration
export PARALLEL="true"
export PUSH="false"
```

## Prerequisites

### Production Deployment
- Kubernetes cluster (1.24+)
- kubectl configured
- kustomize
- Docker (for image building)
- Minimum cluster resources:
  - 3 nodes (recommended)
  - 8GB RAM per node
  - 4 CPU cores per node

### Development Environment
- Docker Desktop or Docker Engine
- 8GB RAM minimum (16GB recommended)
- 4 CPU cores minimum
- 20GB disk space

## Security Considerations

### Secrets Management

Before deployment, update the secrets in `k8s/secrets.yaml`:

1. **Generate secure passwords:**
   ```bash
   # PostgreSQL password
   openssl rand -base64 32

   # Redis password
   openssl rand -base64 32

   # JWT secret
   openssl rand -base64 64

   # Encryption key
   openssl rand -base64 32
   ```

2. **Encode to base64:**
   ```bash
   echo -n "your-password" | base64
   ```

3. **Update registry credentials:**
   ```bash
   kubectl create secret docker-registry kubenexus-registry-secret \
     --docker-server=your-registry.com \
     --docker-username=username \
     --docker-password=password \
     --dry-run=client -o yaml
   ```

### RBAC Configuration

The cluster-manager-service requires cluster-wide permissions for Kubernetes management. Review and adjust the RBAC configuration in `k8s/cluster-manager-service.yaml` based on your security requirements.

## Troubleshooting

### Common Issues

1. **Images not found:**
   - Ensure images are built and pushed to the correct registry
   - Check registry credentials and access

2. **Ingress not accessible:**
   - Verify NGINX Ingress Controller is running
   - Check DNS configuration
   - Ensure load balancer has external IP

3. **Services not starting:**
   - Check resource limits and node capacity
   - Verify database connectivity
   - Check secrets configuration

4. **Development environment issues:**
   - Ensure minikube has sufficient resources
   - Check local DNS configuration
   - Verify Docker is running

### Debugging Commands

```bash
# Check pod status
kubectl get pods -n kubenexus

# Check service logs
kubectl logs -f deployment/auth-service -n kubenexus

# Check ingress status
kubectl describe ingress kubenexus-ingress -n kubenexus

# Check resource usage
kubectl top nodes
kubectl top pods -n kubenexus

# Check events
kubectl get events -n kubenexus --sort-by='.firstTimestamp'
```

## Development Workflow

### Live Development with Skaffold

```bash
# Start live development (builds and deploys on file changes)
skaffold dev

# Build and deploy once
skaffold run

# Debug mode
skaffold debug
```

### Manual Development Workflow

```bash
# 1. Build images
./scripts/build-images.sh --tag dev --no-push

# 2. Deploy to development
kubectl apply -k k8s/dev

# 3. Port forward for local access
kubectl port-forward service/frontend 3000:80
kubectl port-forward service/api-gateway 8000:8000
```

## Support

For issues and questions:
1. Check this README and script help messages
2. Review Kubernetes events and logs
3. Check the main project README
4. File an issue with detailed information about your environment and error messages 