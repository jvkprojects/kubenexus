#!/bin/bash

# KubeNexus Kubernetes Cleanup Script
# This script removes the KubeNexus platform from Kubernetes

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
FORCE=false

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"

print_banner() {
    echo -e "${BLUE}"
    echo "=========================================="
    echo "    KubeNexus Cleanup Script"
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
    
    print_success "Prerequisites check passed"
}

confirm_deletion() {
    if [ "$FORCE" = "true" ]; then
        return 0
    fi
    
    print_warning "This will permanently delete the KubeNexus platform and all associated data!"
    print_warning "This action cannot be undone."
    echo
    print_info "The following will be deleted:"
    print_info "- All KubeNexus services and deployments"
    print_info "- Database with all user data and clusters"
    print_info "- Persistent volumes and stored data"
    print_info "- SSL certificates"
    print_info "- ConfigMaps and Secrets"
    echo
    
    read -p "Are you sure you want to continue? Type 'DELETE' to confirm: " -r
    echo
    if [[ ! $REPLY == "DELETE" ]]; then
        print_info "Cleanup cancelled"
        exit 0
    fi
}

backup_data() {
    print_step "Creating backup of persistent data..."
    
    # Create backup directory
    local backup_dir="backups/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup PostgreSQL data if possible
    if kubectl get pods -n "$NAMESPACE" -l app=postgres &> /dev/null; then
        print_info "Backing up PostgreSQL data..."
        local postgres_pod
        postgres_pod=$(kubectl get pods -n "$NAMESPACE" -l app=postgres -o jsonpath='{.items[0].metadata.name}')
        
        if [ -n "$postgres_pod" ]; then
            kubectl exec -n "$NAMESPACE" "$postgres_pod" -- pg_dumpall -U postgres > "$backup_dir/postgres_backup.sql" || true
            print_info "PostgreSQL backup saved to $backup_dir/postgres_backup.sql"
        fi
    fi
    
    # Backup configurations
    print_info "Backing up Kubernetes configurations..."
    kubectl get all,pvc,configmaps,secrets,ingress -n "$NAMESPACE" -o yaml > "$backup_dir/kubernetes_resources.yaml" || true
    
    print_success "Backup completed in $backup_dir"
}

delete_application() {
    print_step "Deleting KubeNexus application..."
    
    cd "$PROJECT_ROOT"
    
    # Delete using kustomize if available
    if command -v kustomize &> /dev/null && [ -f "$KUSTOMIZE_DIR/kustomization.yaml" ]; then
        print_info "Deleting using kustomize..."
        kustomize build "$KUSTOMIZE_DIR" | kubectl delete -f - --ignore-not-found=true
    else
        # Fallback to manual deletion
        print_info "Deleting resources manually..."
        
        # Delete deployments
        kubectl delete deployments --all -n "$NAMESPACE" --ignore-not-found=true
        
        # Delete services
        kubectl delete services --all -n "$NAMESPACE" --ignore-not-found=true
        
        # Delete ingress
        kubectl delete ingress --all -n "$NAMESPACE" --ignore-not-found=true
        
        # Delete configmaps
        kubectl delete configmaps --all -n "$NAMESPACE" --ignore-not-found=true
        
        # Delete secrets
        kubectl delete secrets --all -n "$NAMESPACE" --ignore-not-found=true
        
        # Delete PVCs
        kubectl delete pvc --all -n "$NAMESPACE" --ignore-not-found=true
        
        # Delete service accounts
        kubectl delete serviceaccounts --all -n "$NAMESPACE" --ignore-not-found=true
    fi
    
    print_success "Application resources deleted"
}

delete_rbac() {
    print_step "Deleting RBAC resources..."
    
    # Delete cluster-wide RBAC resources
    kubectl delete clusterrole cluster-manager-role --ignore-not-found=true
    kubectl delete clusterrolebinding cluster-manager-binding --ignore-not-found=true
    
    print_success "RBAC resources deleted"
}

delete_namespace() {
    print_step "Deleting namespace..."
    
    if kubectl get namespace "$NAMESPACE" &> /dev/null; then
        kubectl delete namespace "$NAMESPACE"
        
        # Wait for namespace to be fully deleted
        print_info "Waiting for namespace to be fully deleted..."
        while kubectl get namespace "$NAMESPACE" &> /dev/null; do
            sleep 5
        done
        
        print_success "Namespace deleted"
    else
        print_info "Namespace $NAMESPACE does not exist"
    fi
}

cleanup_certificates() {
    print_step "Cleaning up certificates..."
    
    # Delete certificate resources if they exist
    kubectl delete certificate kubenexus-tls --ignore-not-found=true
    kubectl delete certificaterequest --all --ignore-not-found=true
    
    print_success "Certificates cleaned up"
}

cleanup_persistent_volumes() {
    print_step "Cleaning up persistent volumes..."
    
    # Find and delete PVs that were bound to KubeNexus PVCs
    local pvs
    pvs=$(kubectl get pv -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.claimRef.namespace}{" "}{.spec.claimRef.name}{"\n"}{end}' | grep "$NAMESPACE" | awk '{print $1}' || true)
    
    if [ -n "$pvs" ]; then
        print_info "Found persistent volumes to clean up:"
        echo "$pvs"
        
        for pv in $pvs; do
            kubectl delete pv "$pv" --ignore-not-found=true
        done
        
        print_success "Persistent volumes cleaned up"
    else
        print_info "No persistent volumes to clean up"
    fi
}

verify_cleanup() {
    print_step "Verifying cleanup..."
    
    # Check if namespace still exists
    if kubectl get namespace "$NAMESPACE" &> /dev/null; then
        print_warning "Namespace $NAMESPACE still exists"
    else
        print_success "✓ Namespace deleted"
    fi
    
    # Check for remaining RBAC resources
    if kubectl get clusterrole cluster-manager-role &> /dev/null; then
        print_warning "ClusterRole cluster-manager-role still exists"
    else
        print_success "✓ ClusterRole deleted"
    fi
    
    if kubectl get clusterrolebinding cluster-manager-binding &> /dev/null; then
        print_warning "ClusterRoleBinding cluster-manager-binding still exists"
    else
        print_success "✓ ClusterRoleBinding deleted"
    fi
    
    # Check for remaining PVs
    local remaining_pvs
    remaining_pvs=$(kubectl get pv -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.claimRef.namespace}{"\n"}{end}' | grep "$NAMESPACE" | awk '{print $1}' || true)
    
    if [ -n "$remaining_pvs" ]; then
        print_warning "Some persistent volumes still exist:"
        echo "$remaining_pvs"
    else
        print_success "✓ All persistent volumes cleaned up"
    fi
}

show_status() {
    print_step "Final status..."
    
    echo
    print_success "KubeNexus cleanup completed!"
    
    print_info "Summary:"
    print_info "- Application resources: Deleted"
    print_info "- Namespace: Deleted"
    print_info "- RBAC resources: Deleted"
    print_info "- Persistent volumes: Cleaned up"
    print_info "- Certificates: Cleaned up"
    
    if [ -d "backups" ]; then
        echo
        print_info "Backups are available in the 'backups' directory"
        print_info "You can restore from these backups if needed"
    fi
}

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Clean up KubeNexus platform from Kubernetes"
    echo
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  --force                 Skip confirmation prompts"
    echo "  --no-backup            Skip data backup"
    echo "  --namespace NAMESPACE   Target namespace (default: kubenexus)"
    echo "  --keep-namespace        Don't delete the namespace"
    echo "  --keep-pvs              Don't delete persistent volumes"
    echo "  --rbac-only             Only delete RBAC resources"
    echo "  --verify-only           Only verify what would be deleted"
    echo
    echo "Examples:"
    echo "  $0                      # Interactive cleanup with backup"
    echo "  $0 --force --no-backup  # Force cleanup without backup"
    echo "  $0 --verify-only        # Show what would be deleted"
}

main() {
    local no_backup=false
    local keep_namespace=false
    local keep_pvs=false
    local rbac_only=false
    local verify_only=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            --force)
                FORCE=true
                shift
                ;;
            --no-backup)
                no_backup=true
                shift
                ;;
            --namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            --keep-namespace)
                keep_namespace=true
                shift
                ;;
            --keep-pvs)
                keep_pvs=true
                shift
                ;;
            --rbac-only)
                rbac_only=true
                shift
                ;;
            --verify-only)
                verify_only=true
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
    
    if [ "$verify_only" = "true" ]; then
        print_step "Verification mode - showing what would be deleted..."
        
        print_info "Namespace: $NAMESPACE"
        if kubectl get namespace "$NAMESPACE" &> /dev/null; then
            kubectl get all,pvc,configmaps,secrets,ingress -n "$NAMESPACE"
        else
            print_info "Namespace $NAMESPACE does not exist"
        fi
        
        print_info "RBAC resources:"
        kubectl get clusterrole cluster-manager-role 2>/dev/null || echo "  ClusterRole not found"
        kubectl get clusterrolebinding cluster-manager-binding 2>/dev/null || echo "  ClusterRoleBinding not found"
        
        exit 0
    fi
    
    if [ "$rbac_only" = "true" ]; then
        confirm_deletion
        delete_rbac
        print_success "RBAC cleanup completed"
        exit 0
    fi
    
    confirm_deletion
    
    if [ "$no_backup" = "false" ]; then
        backup_data
    fi
    
    delete_application
    delete_rbac
    cleanup_certificates
    
    if [ "$keep_pvs" = "false" ]; then
        cleanup_persistent_volumes
    fi
    
    if [ "$keep_namespace" = "false" ]; then
        delete_namespace
    fi
    
    verify_cleanup
    show_status
}

# Run main function with all arguments
main "$@" 