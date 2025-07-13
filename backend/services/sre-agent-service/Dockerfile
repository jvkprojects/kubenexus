# KubeNexus SRE Agent Service Dockerfile
# Multi-stage build for production-ready container with ML dependencies

# Build stage
FROM python:3.11-slim as builder

# Set build arguments
ARG BUILD_ENV=production

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies for ML libraries
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    gcc \
    g++ \
    gfortran \
    libopenblas-dev \
    liblapack-dev \
    && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY services/sre-agent-service/requirements.txt .
COPY shared/requirements.txt ./shared_requirements.txt

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt && \
    pip install -r shared_requirements.txt

# Production stage
FROM python:3.11-slim as production

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app:/app/shared"

# Install runtime dependencies for ML libraries
RUN apt-get update && apt-get install -y \
    curl \
    libopenblas0 \
    liblapack3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r kubenexus \
    && useradd -r -g kubenexus kubenexus

# Set work directory
WORKDIR /app

# Copy Python packages from builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy shared utilities
COPY shared ./shared

# Copy application code
COPY services/sre-agent-service .

# Create directories for ML models
RUN mkdir -p /app/models && chown -R kubenexus:kubenexus /app

# Switch to non-root user
USER kubenexus

# Expose port
EXPOSE 8002

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8002/health || exit 1

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002", "--workers", "1"] 