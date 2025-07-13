# KubeNexus Enterprise SaaS Platform

## 🚀 Overview

KubeNexus is a production-ready, enterprise-grade SaaS platform that serves as a comprehensive Kubernetes Control Plane. It provides a unified dashboard for managing diverse Kubernetes clusters (public cloud-managed and on-premises) with an AI-powered SRE agent for proactive issue resolution.

## 🏗️ Architecture

### Core Principles
- **Microservices Architecture**: Loosely coupled services
- **API-First Design**: Well-documented APIs for all functionality  
- **Security by Design**: Robust authentication, authorization, and data security
- **Scalability**: Horizontal scalability across all layers
- **Observability**: Comprehensive logging, monitoring, and tracing
- **Automated Testing**: Unit, integration, and end-to-end tests
- **Infrastructure as Code**: Deployment scripts for various environments

### Technology Stack
- **Backend**: Python with FastAPI
- **Frontend**: React with Bootstrap 5
- **Database**: PostgreSQL (primary), Redis (caching/sessions)
- **Containerization**: Docker & Docker Compose
- **Orchestration**: Kubernetes
- **AI/ML**: Scikit-learn, TensorFlow Lite for SRE agent

## 📁 Project Structure

```
KubeNexus/
├── backend/
│   ├── services/
│   │   ├── auth-service/
│   │   ├── cluster-manager-service/
│   │   ├── api-gateway/
│   │   ├── sre-agent-service/
│   │   ├── audit-log-service/
│   │   ├── metrics-service/
│   │   └── terminal-service/
│   ├── shared/
│   └── database/
├── frontend/
│   ├── src/
│   ├── public/
│   └── tests/
├── k8s/
├── docker/
├── tests/
├── docs/
└── scripts/
```

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.11+
- Node.js 18+
- Kubernetes cluster (for K8s deployment)

### Local Development with Docker Compose

1. **Clone and setup**:
   ```bash
   cd KubeNexus
   cp .env.example .env
   # Edit .env with your configuration
   ```

2. **Start the platform**:
   ```bash
   docker compose up -d --build
   ```

3. **Access the application**:
   - Frontend: http://localhost:3000
   - API Gateway: http://localhost:80
   - API Documentation: http://localhost:80/docs

### Kubernetes Deployment

1. **Deploy to Kubernetes**:
   ```bash
   ./scripts/deploy-k8s.sh
   ```

2. **Access via Ingress**:
   - Configure your DNS to point to the Ingress controller
   - Access via configured hostname

## 🔧 Features

### Core Features
- **Multi-Cluster Management**: Support for on-premises, EKS, GKE, AKS clusters
- **Unified Dashboard**: Aggregated view across all registered clusters
- **RBAC**: Fine-grained role-based access control
- **Real-time Monitoring**: Live metrics and resource monitoring
- **Terminal Access**: Web-based kubectl terminal
- **Log Streaming**: Real-time log viewing
- **Resource Management**: CRUD operations for K8s resources

### AI-Powered SRE Agent
- **Proactive Monitoring**: Continuous scanning for issues
- **Anomaly Detection**: ML-based detection of performance bottlenecks
- **Root Cause Analysis**: Intelligent problem identification
- **Resolution Suggestions**: Actionable remediation steps
- **Severity Classification**: Priority-based issue handling

### Security Features
- **Multi-Auth Support**: Local, SSO, LDAP, Active Directory
- **JWT Authentication**: Secure token-based auth
- **Data Encryption**: AES-256 encryption for sensitive data
- **Audit Logging**: Comprehensive audit trail
- **Network Security**: Network policies and secure communication

## 📊 API Documentation

Once running, access the interactive API documentation:
- **Swagger UI**: http://localhost:80/docs
- **ReDoc**: http://localhost:80/redoc

## 🧪 Testing

### Run Tests
```bash
# Backend tests
cd backend && python -m pytest

# Frontend tests  
cd frontend && npm test

# E2E tests
cd tests && npx cypress run
```

### Test Coverage
```bash
# Backend coverage
cd backend && python -m pytest --cov=services

# Frontend coverage
cd frontend && npm run test:coverage
```

## 🔧 Development

### Backend Development
```bash
cd backend/services/auth-service
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Frontend Development
```bash
cd frontend
npm install
npm start
```

## 📈 Monitoring & Observability

- **Logs**: Structured JSON logging across all services
- **Metrics**: Prometheus-compatible metrics endpoints
- **Tracing**: OpenTelemetry integration
- **Health Checks**: Service health monitoring endpoints

## 🔐 Security

### Environment Variables
- Store sensitive data in environment variables
- Use Kubernetes secrets for production deployment
- Rotate keys and credentials regularly

### Database Security
- Encrypted connections (SSL/TLS)
- Encrypted sensitive data at rest
- Connection pooling and query optimization

## 🚀 Deployment Options

1. **Docker Compose** (Development/Testing)
2. **Kubernetes** (Production)
3. **Cloud Platforms** (AWS, GCP, Azure)

## 📚 Documentation

- [API Documentation](./docs/api.md)
- [Deployment Guide](./docs/deployment.md)
- [Development Guide](./docs/development.md)
- [Security Guide](./docs/security.md)
- [Troubleshooting](./docs/troubleshooting.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: GitHub Issues
- **Documentation**: `/docs` folder
- **Community**: [Discord/Slack link]

---

**KubeNexus** - Your Enterprise Kubernetes Control Plane 