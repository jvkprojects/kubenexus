#!/bin/bash

# KubeNexus Docker Images Build Script
# This script builds and pushes all Docker images for the KubeNexus platform

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REGISTRY="${REGISTRY:-kubenexus}"
TAG="${TAG:-v1.0.0}"
PUSH="${PUSH:-true}"
PARALLEL="${PARALLEL:-false}"

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"

# Services to build
BACKEND_SERVICES=(
    "auth-service"
    "cluster-manager-service"
    "api-gateway"
    "sre-agent-service"
    "audit-log-service"
    "metrics-service"
    "terminal-service"
)

print_banner() {
    echo -e "${BLUE}"
    echo "=========================================="
    echo "    KubeNexus Image Build Script"
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

check_prerequisites() {
    print_step "Checking prerequisites..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running"
        exit 1
    fi
    
    # Check if we can pull base images
    print_info "Testing Docker registry access..."
    if ! docker pull python:3.11-slim &> /dev/null; then
        print_error "Cannot pull base images. Check your internet connection."
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

build_backend_service() {
    local service=$1
    local service_dir="$PROJECT_ROOT/backend/services/$service"
    
    print_info "Building $service..."
    
    if [ ! -f "$service_dir/Dockerfile" ]; then
        print_error "Dockerfile not found for $service"
        return 1
    fi
    
    # Build the image
    docker build \
        --tag "$REGISTRY/$service:$TAG" \
        --tag "$REGISTRY/$service:latest" \
        --file "$service_dir/Dockerfile" \
        "$PROJECT_ROOT/backend" \
        --build-arg SERVICE_NAME="$service" \
        --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --build-arg VCS_REF="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
    
    print_success "Built $service successfully"
    
    # Push if enabled
    if [ "$PUSH" = "true" ]; then
        print_info "Pushing $service..."
        docker push "$REGISTRY/$service:$TAG"
        docker push "$REGISTRY/$service:latest"
        print_success "Pushed $service successfully"
    fi
}

build_frontend() {
    print_info "Building frontend..."
    
    local frontend_dir="$PROJECT_ROOT/frontend"
    
    if [ ! -f "$frontend_dir/Dockerfile" ]; then
        print_error "Dockerfile not found for frontend"
        return 1
    fi
    
    # Build the frontend image
    docker build \
        --tag "$REGISTRY/frontend:$TAG" \
        --tag "$REGISTRY/frontend:latest" \
        --file "$frontend_dir/Dockerfile" \
        "$frontend_dir" \
        --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --build-arg VCS_REF="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
    
    print_success "Built frontend successfully"
    
    # Push if enabled
    if [ "$PUSH" = "true" ]; then
        print_info "Pushing frontend..."
        docker push "$REGISTRY/frontend:$TAG"
        docker push "$REGISTRY/frontend:latest"
        print_success "Pushed frontend successfully"
    fi
}

build_all_parallel() {
    print_step "Building all images in parallel..."
    
    local pids=()
    
    # Build backend services in parallel
    for service in "${BACKEND_SERVICES[@]}"; do
        (build_backend_service "$service") &
        pids+=($!)
    done
    
    # Build frontend in parallel
    (build_frontend) &
    pids+=($!)
    
    # Wait for all builds to complete
    local failed=0
    for pid in "${pids[@]}"; do
        if ! wait "$pid"; then
            failed=1
        fi
    done
    
    if [ $failed -eq 1 ]; then
        print_error "Some builds failed"
        exit 1
    fi
    
    print_success "All images built successfully"
}

build_all_sequential() {
    print_step "Building all images sequentially..."
    
    # Build backend services
    for service in "${BACKEND_SERVICES[@]}"; do
        build_backend_service "$service"
    done
    
    # Build frontend
    build_frontend
    
    print_success "All images built successfully"
}

show_images() {
    print_step "Built images summary..."
    
    echo
    print_info "Backend services:"
    for service in "${BACKEND_SERVICES[@]}"; do
        echo "  $REGISTRY/$service:$TAG"
    done
    
    echo
    print_info "Frontend:"
    echo "  $REGISTRY/frontend:$TAG"
    
    echo
    print_info "Docker images:"
    docker images | grep "$REGISTRY" | head -20
}

cleanup_old_images() {
    print_step "Cleaning up old images..."
    
    # Remove dangling images
    local dangling_images
    dangling_images=$(docker images -f "dangling=true" -q)
    if [ -n "$dangling_images" ]; then
        docker rmi $dangling_images
        print_success "Removed dangling images"
    else
        print_info "No dangling images to remove"
    fi
    
    # Remove old builds (keep last 3 versions)
    for service in "${BACKEND_SERVICES[@]}" "frontend"; do
        local old_images
        old_images=$(docker images "$REGISTRY/$service" --format "table {{.Repository}}:{{.Tag}}" | grep -v "TAG\|latest" | tail -n +4)
        if [ -n "$old_images" ]; then
            echo "$old_images" | xargs -r docker rmi
            print_info "Cleaned up old images for $service"
        fi
    done
}

validate_images() {
    print_step "Validating built images..."
    
    local failed=0
    
    # Check backend services
    for service in "${BACKEND_SERVICES[@]}"; do
        if ! docker inspect "$REGISTRY/$service:$TAG" &> /dev/null; then
            print_error "Image not found: $REGISTRY/$service:$TAG"
            failed=1
        else
            print_info "✓ $REGISTRY/$service:$TAG"
        fi
    done
    
    # Check frontend
    if ! docker inspect "$REGISTRY/frontend:$TAG" &> /dev/null; then
        print_error "Image not found: $REGISTRY/frontend:$TAG"
        failed=1
    else
        print_info "✓ $REGISTRY/frontend:$TAG"
    fi
    
    if [ $failed -eq 1 ]; then
        print_error "Image validation failed"
        exit 1
    fi
    
    print_success "All images validated successfully"
}

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Build and push Docker images for KubeNexus platform"
    echo
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  --registry REGISTRY     Docker registry (default: kubenexus)"
    echo "  --tag TAG               Docker image tag (default: v1.0.0)"
    echo "  --no-push              Don't push images to registry"
    echo "  --parallel             Build images in parallel"
    echo "  --service SERVICE      Build only specific service"
    echo "  --frontend-only        Build only frontend"
    echo "  --backend-only         Build only backend services"
    echo "  --cleanup              Clean up old images after build"
    echo "  --validate-only        Only validate existing images"
    echo
    echo "Environment variables:"
    echo "  REGISTRY               Docker registry prefix"
    echo "  TAG                    Docker image tag"
    echo "  PUSH                   Push images (true/false)"
    echo "  PARALLEL               Build in parallel (true/false)"
    echo
    echo "Examples:"
    echo "  $0                                    # Build all images"
    echo "  $0 --parallel --tag v1.1.0           # Build in parallel with custom tag"
    echo "  $0 --service auth-service --no-push  # Build only auth service locally"
    echo "  $0 --frontend-only                   # Build only frontend"
}

main() {
    local service_only=""
    local frontend_only=false
    local backend_only=false
    local cleanup=false
    local validate_only=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            --registry)
                REGISTRY="$2"
                shift 2
                ;;
            --tag)
                TAG="$2"
                shift 2
                ;;
            --no-push)
                PUSH="false"
                shift
                ;;
            --parallel)
                PARALLEL="true"
                shift
                ;;
            --service)
                service_only="$2"
                shift 2
                ;;
            --frontend-only)
                frontend_only=true
                shift
                ;;
            --backend-only)
                backend_only=true
                shift
                ;;
            --cleanup)
                cleanup=true
                shift
                ;;
            --validate-only)
                validate_only=true
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
    
    print_info "Configuration:"
    print_info "  Registry: $REGISTRY"
    print_info "  Tag: $TAG"
    print_info "  Push: $PUSH"
    print_info "  Parallel: $PARALLEL"
    
    if [ "$validate_only" = "true" ]; then
        validate_images
        exit 0
    fi
    
    check_prerequisites
    
    # Build based on options
    if [ -n "$service_only" ]; then
        build_backend_service "$service_only"
    elif [ "$frontend_only" = "true" ]; then
        build_frontend
    elif [ "$backend_only" = "true" ]; then
        for service in "${BACKEND_SERVICES[@]}"; do
            build_backend_service "$service"
        done
    elif [ "$PARALLEL" = "true" ]; then
        build_all_parallel
    else
        build_all_sequential
    fi
    
    validate_images
    show_images
    
    if [ "$cleanup" = "true" ]; then
        cleanup_old_images
    fi
    
    print_success "Build process completed successfully!"
}

# Run main function with all arguments
main "$@" 