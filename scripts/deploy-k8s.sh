#!/bin/bash

# KubeNexus Kubernetes Deployment Script
# This script deploys the complete KubeNexus platform to Kubernetes

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="kubenexus"
KUSTOMIZE_DIR="k8s"
REGISTRY="kubenexus"
TAG="${TAG:-v1.0.0}"
DOMAIN="${DOMAIN:-kubenexus.example.com}"
API_DOMAIN="${API_DOMAIN:-api.kubenexus.example.com}"

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"

print_banner() {
    echo -e "${BLUE}"
    echo "=========================================="
    echo "    KubeNexus Deployment Script"
    echo "=========================================="
    echo -e "${NC}"
}

print_step() {
    echo -e "${YELLOW}[STEP]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

check_prerequisites() {
    print_step "Checking prerequisites..."
    
    # Check if kubectl is installed and configured
    if ! command -v kubectl &> /dev/null; then
        print_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    # Check if kustomize is installed
    if ! command -v kustomize &> /dev/null; then
        print_error "kustomize is not installed or not in PATH"
        exit 1
    fi
    
    # Check if we can connect to the cluster
    if ! kubectl cluster-info &> /dev/null; then
        print_error "Cannot connect to Kubernetes cluster. Please check your kubeconfig."
        exit 1
    fi
    
    # Check if Docker is installed (for image building)
    if ! command -v docker &> /dev/null; then
        print_warning "Docker is not installed. You'll need to build and push images manually."
    fi
    
    print_success "Prerequisites check passed"
}

validate_environment() {
    print_step "Validating environment..."
    
    # Check if namespace exists
    if kubectl get namespace "$NAMESPACE" &> /dev/null; then
        print_info "Namespace '$NAMESPACE' already exists"
    else
        print_info "Namespace '$NAMESPACE' will be created"
    fi
    
    # Check cluster resources
    local node_count
    node_count=$(kubectl get nodes --no-headers | wc -l)
    print_info "Cluster has $node_count nodes"
    
    if [ "$node_count" -lt 3 ]; then
        print_warning "Cluster has less than 3 nodes. Consider scaling for production workloads."
    fi
    
    print_success "Environment validation completed"
}

setup_prerequisites() {
    print_step "Setting up prerequisites..."
    
    # Install NGINX Ingress Controller if not present
    if ! kubectl get pods -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx &> /dev/null; then
        print_info "Installing NGINX Ingress Controller..."
        kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.2/deploy/static/provider/cloud/deploy.yaml
        
        print_info "Waiting for NGINX Ingress Controller to be ready..."
        kubectl wait --namespace ingress-nginx \
            --for=condition=ready pod \
            --selector=app.kubernetes.io/component=controller \
            --timeout=300s
    else
        print_info "NGINX Ingress Controller already installed"
    fi
    
    # Install cert-manager if not present
    if ! kubectl get pods -n cert-manager -l app.kubernetes.io/name=cert-manager &> /dev/null; then
        print_info "Installing cert-manager..."
        kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.2/cert-manager.yaml
        
        print_info "Waiting for cert-manager to be ready..."
        kubectl wait --namespace cert-manager \
            --for=condition=ready pod \
            --selector=app.kubernetes.io/name=cert-manager \
            --timeout=300s
            
        # Create ClusterIssuer for Let's Encrypt
        cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@${DOMAIN}
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
EOF
    else
        print_info "cert-manager already installed"
    fi
    
    print_success "Prerequisites setup completed"
}

update_secrets() {
    print_step "Updating secrets configuration..."
    
    # Update domain in ingress
    if [ -f "$PROJECT_ROOT/$KUSTOMIZE_DIR/ingress.yaml" ]; then
        sed -i.bak "s/kubenexus\.example\.com/$DOMAIN/g" "$PROJECT_ROOT/$KUSTOMIZE_DIR/ingress.yaml"
        sed -i.bak "s/api\.kubenexus\.example\.com/$API_DOMAIN/g" "$PROJECT_ROOT/$KUSTOMIZE_DIR/ingress.yaml"
        rm -f "$PROJECT_ROOT/$KUSTOMIZE_DIR/ingress.yaml.bak"
    fi
    
    # Update frontend configuration
    if [ -f "$PROJECT_ROOT/$KUSTOMIZE_DIR/frontend.yaml" ]; then
        sed -i.bak "s/api\.kubenexus\.example\.com/$API_DOMAIN/g" "$PROJECT_ROOT/$KUSTOMIZE_DIR/frontend.yaml"
        rm -f "$PROJECT_ROOT/$KUSTOMIZE_DIR/frontend.yaml.bak"
    fi
    
    print_warning "Please update the base64 encoded secrets in k8s/secrets.yaml with your actual values:"
    print_info "- POSTGRES_PASSWORD"
    print_info "- REDIS_PASSWORD"
    print_info "- JWT_SECRET_KEY"
    print_info "- ENCRYPTION_KEY"
    print_info "- Registry credentials in kubenexus-registry-secret"
    
    read -p "Have you updated the secrets? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_error "Please update the secrets before continuing deployment"
        exit 1
    fi
    
    print_success "Secrets validation completed"
}

deploy_application() {
    print_step "Deploying KubeNexus application..."
    
    cd "$PROJECT_ROOT"
    
    # Apply kustomization
    print_info "Applying Kubernetes manifests..."
    kustomize build "$KUSTOMIZE_DIR" | kubectl apply -f -
    
    print_success "Application manifests applied"
}

wait_for_deployment() {
    print_step "Waiting for deployments to be ready..."
    
    local deployments=(
        "postgres"
        "redis"
        "auth-service"
        "cluster-manager-service"
        "api-gateway"
        "sre-agent-service"
        "audit-log-service"
        "metrics-service"
        "terminal-service"
        "frontend"
    )
    
    for deployment in "${deployments[@]}"; do
        print_info "Waiting for deployment: $deployment"
        kubectl wait --for=condition=available --timeout=300s deployment/"$deployment" -n "$NAMESPACE"
    done
    
    print_success "All deployments are ready"
}

check_ingress() {
    print_step "Checking ingress configuration..."
    
    # Wait for ingress to get IP
    print_info "Waiting for ingress to get external IP..."
    while true; do
        EXTERNAL_IP=$(kubectl get ingress kubenexus-ingress -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")
        if [ -n "$EXTERNAL_IP" ] && [ "$EXTERNAL_IP" != "null" ]; then
            break
        fi
        sleep 10
    done
    
    print_success "Ingress external IP: $EXTERNAL_IP"
    print_info "Please configure your DNS to point:"
    print_info "  $DOMAIN -> $EXTERNAL_IP"
    print_info "  $API_DOMAIN -> $EXTERNAL_IP"
}

show_status() {
    print_step "Deployment status summary..."
    
    echo
    print_info "Pods status:"
    kubectl get pods -n "$NAMESPACE"
    
    echo
    print_info "Services status:"
    kubectl get services -n "$NAMESPACE"
    
    echo
    print_info "Ingress status:"
    kubectl get ingress -n "$NAMESPACE"
    
    echo
    print_success "KubeNexus deployment completed successfully!"
    print_info "Frontend URL: https://$DOMAIN"
    print_info "API URL: https://$API_DOMAIN"
    print_info "Default admin credentials: admin / admin123!"
}

cleanup_on_error() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        print_error "Deployment failed with exit code $exit_code"
        print_info "To cleanup partial deployment, run: ./scripts/cleanup-k8s.sh"
    fi
    exit $exit_code
}

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Deploy KubeNexus platform to Kubernetes"
    echo
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  --tag TAG               Docker image tag (default: v1.0.0)"
    echo "  --domain DOMAIN         Main domain (default: kubenexus.example.com)"
    echo "  --api-domain DOMAIN     API domain (default: api.kubenexus.example.com)"
    echo "  --skip-prerequisites    Skip prerequisites installation"
    echo "  --skip-secrets-check    Skip secrets validation"
    echo "  --dry-run              Show what would be deployed without applying"
    echo
    echo "Environment variables:"
    echo "  TAG                     Docker image tag"
    echo "  DOMAIN                  Main domain"
    echo "  API_DOMAIN             API domain"
    echo
    echo "Examples:"
    echo "  $0                                                    # Deploy with defaults"
    echo "  $0 --domain kubenexus.mydomain.com                   # Deploy with custom domain"
    echo "  $0 --tag v1.1.0 --skip-prerequisites                 # Deploy specific version"
}

main() {
    local skip_prerequisites=false
    local skip_secrets_check=false
    local dry_run=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            --tag)
                TAG="$2"
                shift 2
                ;;
            --domain)
                DOMAIN="$2"
                API_DOMAIN="api.$2"
                shift 2
                ;;
            --api-domain)
                API_DOMAIN="$2"
                shift 2
                ;;
            --skip-prerequisites)
                skip_prerequisites=true
                shift
                ;;
            --skip-secrets-check)
                skip_secrets_check=true
                shift
                ;;
            --dry-run)
                dry_run=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Set trap for cleanup on error
    trap cleanup_on_error ERR
    
    print_banner
    
    check_prerequisites
    validate_environment
    
    if [ "$skip_prerequisites" = false ]; then
        setup_prerequisites
    else
        print_info "Skipping prerequisites installation"
    fi
    
    if [ "$skip_secrets_check" = false ]; then
        update_secrets
    else
        print_info "Skipping secrets validation"
    fi
    
    if [ "$dry_run" = true ]; then
        print_info "Dry run mode - showing what would be deployed:"
        cd "$PROJECT_ROOT"
        kustomize build "$KUSTOMIZE_DIR"
        exit 0
    fi
    
    deploy_application
    wait_for_deployment
    check_ingress
    show_status
}

# Run main function with all arguments
main "$@" 