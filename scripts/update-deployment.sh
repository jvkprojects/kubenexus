#!/bin/bash

# KubeNexus Deployment Update Script
# This script updates an existing KubeNexus deployment

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
OLD_TAG=""
NEW_TAG=""
ROLLBACK=false
STRATEGY="RollingUpdate"

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"

# Services
SERVICES=(
    "auth-service"
    "cluster-manager-service"
    "api-gateway"
    "sre-agent-service"
    "audit-log-service"
    "metrics-service"
    "terminal-service"
    "frontend"
)

print_banner() {
    echo -e "${BLUE}"
    echo "=========================================="
    echo "    KubeNexus Update Script"
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
    
    # Check if we can connect to the cluster
    if ! kubectl cluster-info &> /dev/null; then
        print_error "Cannot connect to Kubernetes cluster. Please check your kubeconfig."
        exit 1
    fi
    
    # Check if namespace exists
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        print_error "Namespace '$NAMESPACE' does not exist. Please deploy KubeNexus first."
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

get_current_versions() {
    print_step "Getting current deployment versions..."
    
    for service in "${SERVICES[@]}"; do
        local current_image
        current_image=$(kubectl get deployment "$service" -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || echo "not-found")
        
        if [ "$current_image" != "not-found" ]; then
            local current_tag
            current_tag=$(echo "$current_image" | cut -d: -f2)
            print_info "$service: $current_tag"
        else
            print_warning "$service: deployment not found"
        fi
    done
}

validate_new_images() {
    print_step "Validating new images..."
    
    for service in "${SERVICES[@]}"; do
        local image="$REGISTRY/$service:$NEW_TAG"
        
        # Check if image exists (this will depend on your registry)
        if command -v docker &> /dev/null; then
            if ! docker manifest inspect "$image" &> /dev/null; then
                print_warning "Cannot verify image exists: $image"
            else
                print_info "✓ $image"
            fi
        else
            print_info "Skipping image validation (Docker not available)"
            break
        fi
    done
}

backup_current_state() {
    print_step "Backing up current deployment state..."
    
    local backup_dir="backups/update-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup all deployments
    for service in "${SERVICES[@]}"; do
        kubectl get deployment "$service" -n "$NAMESPACE" -o yaml > "$backup_dir/$service-deployment.yaml" 2>/dev/null || true
    done
    
    # Backup other resources
    kubectl get configmaps -n "$NAMESPACE" -o yaml > "$backup_dir/configmaps.yaml"
    kubectl get secrets -n "$NAMESPACE" -o yaml > "$backup_dir/secrets.yaml"
    kubectl get ingress -n "$NAMESPACE" -o yaml > "$backup_dir/ingress.yaml"
    
    print_success "Backup saved to $backup_dir"
}

update_kustomization() {
    print_step "Updating kustomization file..."
    
    local kustomization_file="$PROJECT_ROOT/$KUSTOMIZE_DIR/kustomization.yaml"
    
    if [ -f "$kustomization_file" ]; then
        # Update image tags in kustomization.yaml
        for service in "${SERVICES[@]}"; do
            sed -i.bak "s|name: $REGISTRY/$service.*|name: $REGISTRY/$service\n    newTag: $NEW_TAG|g" "$kustomization_file"
        done
        
        rm -f "$kustomization_file.bak"
        print_success "Kustomization file updated"
    else
        print_warning "Kustomization file not found, will update deployments directly"
    fi
}

update_deployment() {
    local service=$1
    
    print_info "Updating $service..."
    
    # Update the deployment image
    kubectl set image deployment/"$service" \
        "$service=$REGISTRY/$service:$NEW_TAG" \
        -n "$NAMESPACE"
    
    # Set update strategy if specified
    if [ "$STRATEGY" != "RollingUpdate" ]; then
        kubectl patch deployment "$service" -n "$NAMESPACE" -p '{"spec":{"strategy":{"type":"'$STRATEGY'"}}}'
    fi
}

wait_for_rollout() {
    local service=$1
    
    print_info "Waiting for $service rollout to complete..."
    
    # Wait for rollout to complete
    if kubectl rollout status deployment/"$service" -n "$NAMESPACE" --timeout=300s; then
        print_success "$service updated successfully"
        return 0
    else
        print_error "$service update failed"
        return 1
    fi
}

update_all_services() {
    print_step "Updating all services..."
    
    local failed_services=()
    
    for service in "${SERVICES[@]}"; do
        if kubectl get deployment "$service" -n "$NAMESPACE" &> /dev/null; then
            update_deployment "$service"
            
            if ! wait_for_rollout "$service"; then
                failed_services+=("$service")
            fi
        else
            print_warning "Deployment $service not found, skipping"
        fi
    done
    
    if [ ${#failed_services[@]} -gt 0 ]; then
        print_error "The following services failed to update:"
        for service in "${failed_services[@]}"; do
            print_error "  - $service"
        done
        return 1
    fi
    
    print_success "All services updated successfully"
}

update_single_service() {
    local service=$1
    
    print_step "Updating service: $service"
    
    if kubectl get deployment "$service" -n "$NAMESPACE" &> /dev/null; then
        update_deployment "$service"
        wait_for_rollout "$service"
    else
        print_error "Deployment $service not found"
        exit 1
    fi
}

rollback_deployment() {
    local service=$1
    
    print_info "Rolling back $service..."
    
    kubectl rollout undo deployment/"$service" -n "$NAMESPACE"
    
    if wait_for_rollout "$service"; then
        print_success "$service rolled back successfully"
    else
        print_error "$service rollback failed"
    fi
}

perform_rollback() {
    print_step "Performing rollback..."
    
    for service in "${SERVICES[@]}"; do
        if kubectl get deployment "$service" -n "$NAMESPACE" &> /dev/null; then
            rollback_deployment "$service"
        fi
    done
    
    print_success "Rollback completed"
}

health_check() {
    print_step "Performing health checks..."
    
    local unhealthy_services=()
    
    for service in "${SERVICES[@]}"; do
        if kubectl get deployment "$service" -n "$NAMESPACE" &> /dev/null; then
            local ready_replicas
            local desired_replicas
            
            ready_replicas=$(kubectl get deployment "$service" -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
            desired_replicas=$(kubectl get deployment "$service" -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')
            
            if [ "$ready_replicas" = "$desired_replicas" ]; then
                print_info "✓ $service ($ready_replicas/$desired_replicas ready)"
            else
                print_warning "✗ $service ($ready_replicas/$desired_replicas ready)"
                unhealthy_services+=("$service")
            fi
        fi
    done
    
    if [ ${#unhealthy_services[@]} -gt 0 ]; then
        print_warning "Some services are not fully healthy:"
        for service in "${unhealthy_services[@]}"; do
            print_warning "  - $service"
        done
        return 1
    fi
    
    print_success "All services are healthy"
}

show_status() {
    print_step "Deployment status..."
    
    echo
    print_info "Current service versions:"
    for service in "${SERVICES[@]}"; do
        if kubectl get deployment "$service" -n "$NAMESPACE" &> /dev/null; then
            local current_image
            current_image=$(kubectl get deployment "$service" -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.containers[0].image}')
            print_info "  $service: $current_image"
        fi
    done
    
    echo
    print_info "Pod status:"
    kubectl get pods -n "$NAMESPACE"
}

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Update KubeNexus deployment"
    echo
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  --new-tag TAG           New image tag to deploy"
    echo "  --old-tag TAG           Current tag (for verification)"
    echo "  --service SERVICE       Update only specific service"
    echo "  --rollback             Rollback to previous version"
    echo "  --strategy STRATEGY     Update strategy (RollingUpdate|Recreate)"
    echo "  --registry REGISTRY     Docker registry (default: kubenexus)"
    echo "  --namespace NAMESPACE   Target namespace (default: kubenexus)"
    echo "  --no-backup            Skip backup creation"
    echo "  --check-only           Only check current versions"
    echo "  --health-check-only    Only perform health checks"
    echo
    echo "Examples:"
    echo "  $0 --new-tag v1.1.0                    # Update all services"
    echo "  $0 --service auth-service --new-tag v1.1.0  # Update specific service"
    echo "  $0 --rollback                          # Rollback all services"
    echo "  $0 --check-only                        # Check current versions"
}

main() {
    local service_only=""
    local no_backup=false
    local check_only=false
    local health_check_only=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            --new-tag)
                NEW_TAG="$2"
                shift 2
                ;;
            --old-tag)
                OLD_TAG="$2"
                shift 2
                ;;
            --service)
                service_only="$2"
                shift 2
                ;;
            --rollback)
                ROLLBACK=true
                shift
                ;;
            --strategy)
                STRATEGY="$2"
                shift 2
                ;;
            --registry)
                REGISTRY="$2"
                shift 2
                ;;
            --namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            --no-backup)
                no_backup=true
                shift
                ;;
            --check-only)
                check_only=true
                shift
                ;;
            --health-check-only)
                health_check_only=true
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
    
    check_prerequisites
    
    if [ "$check_only" = "true" ]; then
        get_current_versions
        exit 0
    fi
    
    if [ "$health_check_only" = "true" ]; then
        health_check
        exit 0
    fi
    
    if [ "$ROLLBACK" = "true" ]; then
        perform_rollback
        health_check
        show_status
        exit 0
    fi
    
    if [ -z "$NEW_TAG" ]; then
        print_error "New tag is required. Use --new-tag option."
        exit 1
    fi
    
    print_info "Update configuration:"
    print_info "  Registry: $REGISTRY"
    print_info "  New tag: $NEW_TAG"
    print_info "  Strategy: $STRATEGY"
    print_info "  Namespace: $NAMESPACE"
    
    get_current_versions
    validate_new_images
    
    if [ "$no_backup" = "false" ]; then
        backup_current_state
    fi
    
    if [ -n "$service_only" ]; then
        update_single_service "$service_only"
    else
        update_kustomization
        update_all_services
    fi
    
    health_check
    show_status
    
    print_success "Update completed successfully!"
}

# Run main function with all arguments
main "$@" 