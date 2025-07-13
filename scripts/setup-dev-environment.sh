#!/bin/bash

# KubeNexus Development Environment Setup Script
# This script sets up a local development environment for KubeNexus

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DEV_NAMESPACE="kubenexus-dev"
MINIKUBE_PROFILE="kubenexus"
MINIMUM_MEMORY="8192"
MINIMUM_CPUS="4"
LOAD_BALANCER_IP="127.0.0.1"

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"

print_banner() {
    echo -e "${BLUE}"
    echo "=========================================="
    echo "  KubeNexus Development Setup"
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

check_system_requirements() {
    print_step "Checking system requirements..."
    
    # Check OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        print_info "OS: Linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        print_info "OS: macOS"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        print_info "OS: Windows"
    else
        print_warning "Unknown OS: $OSTYPE"
    fi
    
    # Check memory
    if command -v free &> /dev/null; then
        local total_mem
        total_mem=$(free -m | awk 'NR==2{print $2}')
        print_info "Total memory: ${total_mem}MB"
        
        if [ "$total_mem" -lt 8192 ]; then
            print_warning "Recommended minimum memory is 8GB for development"
        fi
    fi
    
    print_success "System requirements check completed"
}

install_prerequisites() {
    print_step "Installing prerequisites..."
    
    # Check and install Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first:"
        print_info "  - Linux: https://docs.docker.com/engine/install/"
        print_info "  - macOS: https://docs.docker.com/docker-for-mac/install/"
        print_info "  - Windows: https://docs.docker.com/docker-for-windows/install/"
        exit 1
    else
        print_success "✓ Docker is installed"
    fi
    
    # Check and install kubectl
    if ! command -v kubectl &> /dev/null; then
        print_info "Installing kubectl..."
        
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
            chmod +x kubectl
            sudo mv kubectl /usr/local/bin/
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/darwin/amd64/kubectl"
            chmod +x kubectl
            sudo mv kubectl /usr/local/bin/
        else
            print_error "Please install kubectl manually for your platform"
            exit 1
        fi
        
        print_success "✓ kubectl installed"
    else
        print_success "✓ kubectl is already installed"
    fi
    
    # Check and install minikube
    if ! command -v minikube &> /dev/null; then
        print_info "Installing minikube..."
        
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
            sudo install minikube-linux-amd64 /usr/local/bin/minikube
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-darwin-amd64
            sudo install minikube-darwin-amd64 /usr/local/bin/minikube
        else
            print_error "Please install minikube manually for your platform"
            exit 1
        fi
        
        print_success "✓ minikube installed"
    else
        print_success "✓ minikube is already installed"
    fi
    
    # Check and install kustomize
    if ! command -v kustomize &> /dev/null; then
        print_info "Installing kustomize..."
        curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh" | bash
        sudo mv kustomize /usr/local/bin/
        print_success "✓ kustomize installed"
    else
        print_success "✓ kustomize is already installed"
    fi
    
    # Check and install skaffold (optional)
    if ! command -v skaffold &> /dev/null; then
        print_info "Installing skaffold..."
        curl -Lo skaffold https://storage.googleapis.com/skaffold/releases/latest/skaffold-linux-amd64
        chmod +x skaffold
        sudo mv skaffold /usr/local/bin/
        print_success "✓ skaffold installed"
    else
        print_success "✓ skaffold is already installed"
    fi
}

setup_minikube() {
    print_step "Setting up minikube cluster..."
    
    # Check if profile exists
    if minikube profile list | grep -q "$MINIKUBE_PROFILE"; then
        print_info "Minikube profile '$MINIKUBE_PROFILE' already exists"
        print_info "Starting existing cluster..."
        minikube start -p "$MINIKUBE_PROFILE"
    else
        print_info "Creating new minikube cluster..."
        minikube start \
            --profile="$MINIKUBE_PROFILE" \
            --memory="$MINIMUM_MEMORY" \
            --cpus="$MINIMUM_CPUS" \
            --disk-size=20g \
            --driver=docker \
            --kubernetes-version=v1.28.0 \
            --addons=ingress,metrics-server,dashboard
    fi
    
    # Set kubectl context
    kubectl config use-context "$MINIKUBE_PROFILE"
    
    print_success "Minikube cluster is ready"
}

enable_addons() {
    print_step "Enabling minikube addons..."
    
    # Enable required addons
    minikube addons enable ingress -p "$MINIKUBE_PROFILE"
    minikube addons enable metrics-server -p "$MINIKUBE_PROFILE"
    minikube addons enable dashboard -p "$MINIKUBE_PROFILE"
    minikube addons enable registry -p "$MINIKUBE_PROFILE"
    
    print_success "Addons enabled"
}

setup_development_namespace() {
    print_step "Setting up development namespace..."
    
    # Create namespace
    kubectl create namespace "$DEV_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Set as default namespace
    kubectl config set-context --current --namespace="$DEV_NAMESPACE"
    
    print_success "Development namespace '$DEV_NAMESPACE' ready"
}

install_development_tools() {
    print_step "Installing development tools..."
    
    # Install cert-manager
    print_info "Installing cert-manager..."
    kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.2/cert-manager.yaml
    
    # Wait for cert-manager to be ready
    kubectl wait --for=condition=available --timeout=300s deployment/cert-manager -n cert-manager
    kubectl wait --for=condition=available --timeout=300s deployment/cert-manager-webhook -n cert-manager
    kubectl wait --for=condition=available --timeout=300s deployment/cert-manager-cainjector -n cert-manager
    
    # Create development ClusterIssuer
    cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned-issuer
spec:
  selfSigned: {}
EOF
    
    print_success "Development tools installed"
}

create_development_configs() {
    print_step "Creating development configurations..."
    
    # Create development kustomization
    local dev_dir="$PROJECT_ROOT/k8s/dev"
    mkdir -p "$dev_dir"
    
    cat <<EOF > "$dev_dir/kustomization.yaml"
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: $DEV_NAMESPACE

resources:
  - ../namespace.yaml
  - ../configmap.yaml
  - ../secrets.yaml
  - ../postgres-init-configmap.yaml
  - ../postgres.yaml
  - ../redis.yaml
  - ../auth-service.yaml
  - ../cluster-manager-service.yaml
  - ../api-gateway.yaml
  - ../sre-agent-service.yaml
  - ../audit-log-service.yaml
  - ../metrics-service.yaml
  - ../terminal-service.yaml
  - ../frontend.yaml
  - ingress-dev.yaml

patches:
  - target:
      kind: Namespace
      name: kubenexus
    patch: |-
      - op: replace
        path: /metadata/name
        value: $DEV_NAMESPACE

images:
  - name: kubenexus/auth-service
    newTag: dev
  - name: kubenexus/cluster-manager-service
    newTag: dev
  - name: kubenexus/api-gateway
    newTag: dev
  - name: kubenexus/sre-agent-service
    newTag: dev
  - name: kubenexus/audit-log-service
    newTag: dev
  - name: kubenexus/metrics-service
    newTag: dev
  - name: kubenexus/terminal-service
    newTag: dev
  - name: kubenexus/frontend
    newTag: dev

commonLabels:
  environment: development

replicas:
  - name: auth-service
    count: 1
  - name: cluster-manager-service
    count: 1
  - name: api-gateway
    count: 1
  - name: sre-agent-service
    count: 1
  - name: audit-log-service
    count: 1
  - name: metrics-service
    count: 1
  - name: terminal-service
    count: 1
  - name: frontend
    count: 1
EOF
    
    # Create development ingress
    cat <<EOF > "$dev_dir/ingress-dev.yaml"
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kubenexus-ingress
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: selfsigned-issuer
spec:
  tls:
  - hosts:
    - kubenexus.local
    - api.kubenexus.local
    secretName: kubenexus-dev-tls
  rules:
  - host: kubenexus.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend
            port:
              number: 80
  - host: api.kubenexus.local
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: api-gateway
            port:
              number: 8000
EOF
    
    print_success "Development configurations created"
}

create_skaffold_config() {
    print_step "Creating Skaffold configuration..."
    
    cat <<EOF > "$PROJECT_ROOT/skaffold.yaml"
apiVersion: skaffold/v4beta7
kind: Config
metadata:
  name: kubenexus
build:
  artifacts:
  - image: kubenexus/auth-service
    context: backend
    docker:
      dockerfile: services/auth-service/Dockerfile
  - image: kubenexus/cluster-manager-service
    context: backend
    docker:
      dockerfile: services/cluster-manager-service/Dockerfile
  - image: kubenexus/api-gateway
    context: backend
    docker:
      dockerfile: services/api-gateway/Dockerfile
  - image: kubenexus/sre-agent-service
    context: backend
    docker:
      dockerfile: services/sre-agent-service/Dockerfile
  - image: kubenexus/audit-log-service
    context: backend
    docker:
      dockerfile: services/audit-log-service/Dockerfile
  - image: kubenexus/metrics-service
    context: backend
    docker:
      dockerfile: services/metrics-service/Dockerfile
  - image: kubenexus/terminal-service
    context: backend
    docker:
      dockerfile: services/terminal-service/Dockerfile
  - image: kubenexus/frontend
    context: frontend
    docker:
      dockerfile: Dockerfile
  tagPolicy:
    envTemplate:
      template: "dev-{{.USER}}-{{.DATE}}"
deploy:
  kustomize:
    paths:
    - k8s/dev
portForward:
- resourceType: service
  resourceName: frontend
  port: 80
  localPort: 3000
- resourceType: service
  resourceName: api-gateway
  port: 8000
  localPort: 8000
EOF
    
    print_success "Skaffold configuration created"
}

setup_local_dns() {
    print_step "Setting up local DNS..."
    
    # Get minikube IP
    local minikube_ip
    minikube_ip=$(minikube ip -p "$MINIKUBE_PROFILE")
    
    print_info "Minikube IP: $minikube_ip"
    
    # Check if entries already exist in /etc/hosts
    if ! grep -q "kubenexus.local" /etc/hosts; then
        print_info "Adding entries to /etc/hosts (requires sudo)..."
        echo "$minikube_ip kubenexus.local" | sudo tee -a /etc/hosts
        echo "$minikube_ip api.kubenexus.local" | sudo tee -a /etc/hosts
        print_success "DNS entries added to /etc/hosts"
    else
        print_info "DNS entries already exist in /etc/hosts"
    fi
}

create_dev_scripts() {
    print_step "Creating development scripts..."
    
    # Create quick development deployment script
    cat <<'EOF' > "$PROJECT_ROOT/scripts/dev-deploy.sh"
#!/bin/bash
# Quick development deployment script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"

echo "Building and deploying KubeNexus for development..."

# Build images
"$SCRIPT_DIR/build-images.sh" --tag dev --parallel

# Deploy to development namespace
kubectl apply -k "$PROJECT_ROOT/k8s/dev"

# Wait for deployments
kubectl wait --for=condition=available --timeout=300s deployment --all -n kubenexus-dev

echo "Development deployment completed!"
echo "Frontend: http://kubenexus.local"
echo "API: http://api.kubenexus.local"
EOF
    
    chmod +x "$PROJECT_ROOT/scripts/dev-deploy.sh"
    
    # Create development cleanup script
    cat <<'EOF' > "$PROJECT_ROOT/scripts/dev-cleanup.sh"
#!/bin/bash
# Development environment cleanup script

set -e

echo "Cleaning up development environment..."

# Delete namespace
kubectl delete namespace kubenexus-dev --ignore-not-found=true

# Clean up Docker images
docker images | grep kubenexus | grep dev | awk '{print $3}' | xargs -r docker rmi

echo "Development environment cleaned up!"
EOF
    
    chmod +x "$PROJECT_ROOT/scripts/dev-cleanup.sh"
    
    print_success "Development scripts created"
}

show_development_info() {
    print_step "Development environment information..."
    
    echo
    print_success "Development environment setup completed!"
    
    print_info "Cluster Information:"
    print_info "  Profile: $MINIKUBE_PROFILE"
    print_info "  Namespace: $DEV_NAMESPACE"
    print_info "  Context: $(kubectl config current-context)"
    
    echo
    print_info "Access URLs:"
    print_info "  Frontend: http://kubenexus.local"
    print_info "  API: http://api.kubenexus.local"
    print_info "  Dashboard: minikube dashboard -p $MINIKUBE_PROFILE"
    
    echo
    print_info "Development Commands:"
    print_info "  Quick deploy: ./scripts/dev-deploy.sh"
    print_info "  Live development: skaffold dev"
    print_info "  Build images: ./scripts/build-images.sh --tag dev"
    print_info "  Cleanup: ./scripts/dev-cleanup.sh"
    
    echo
    print_info "Useful Kubernetes Commands:"
    print_info "  Check pods: kubectl get pods"
    print_info "  Check services: kubectl get services"
    print_info "  Check logs: kubectl logs -f deployment/[service-name]"
    print_info "  Port forward: kubectl port-forward service/[service-name] [local-port]:[service-port]"
}

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Set up KubeNexus development environment"
    echo
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  --profile PROFILE       Minikube profile name (default: kubenexus)"
    echo "  --namespace NAMESPACE   Development namespace (default: kubenexus-dev)"
    echo "  --memory MB             Memory allocation for minikube (default: 8192)"
    echo "  --cpus CPUS             CPU allocation for minikube (default: 4)"
    echo "  --skip-minikube        Skip minikube setup (use existing cluster)"
    echo "  --skip-dns             Skip local DNS setup"
    echo "  --skip-tools           Skip development tools installation"
    echo
    echo "Examples:"
    echo "  $0                      # Full setup with defaults"
    echo "  $0 --memory 16384       # Setup with 16GB memory"
    echo "  $0 --skip-minikube      # Setup on existing cluster"
}

main() {
    local skip_minikube=false
    local skip_dns=false
    local skip_tools=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            --profile)
                MINIKUBE_PROFILE="$2"
                shift 2
                ;;
            --namespace)
                DEV_NAMESPACE="$2"
                shift 2
                ;;
            --memory)
                MINIMUM_MEMORY="$2"
                shift 2
                ;;
            --cpus)
                MINIMUM_CPUS="$2"
                shift 2
                ;;
            --skip-minikube)
                skip_minikube=true
                shift
                ;;
            --skip-dns)
                skip_dns=true
                shift
                ;;
            --skip-tools)
                skip_tools=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    print_banner
    
    check_system_requirements
    install_prerequisites
    
    if [ "$skip_minikube" = "false" ]; then
        setup_minikube
        enable_addons
    fi
    
    setup_development_namespace
    
    if [ "$skip_tools" = "false" ]; then
        install_development_tools
    fi
    
    create_development_configs
    create_skaffold_config
    create_dev_scripts
    
    if [ "$skip_dns" = "false" ]; then
        setup_local_dns
    fi
    
    show_development_info
}

# Run main function with all arguments
main "$@" 