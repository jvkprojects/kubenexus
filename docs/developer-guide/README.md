# KubeNexus Developer Guide

Welcome to the KubeNexus Developer Guide! This documentation is designed for developers who want to contribute to KubeNexus, extend its functionality, or integrate it into their development workflows.

## Table of Contents

1. **[Development Setup](setup.md)**
   - Local development environment
   - Prerequisites and tools
   - Running KubeNexus locally

2. **[Contributing Guidelines](contributing.md)**
   - Code contribution process
   - Code style and standards
   - Pull request guidelines

3. **[Testing Guide](testing.md)**
   - Testing framework and tools
   - Writing unit and integration tests
   - Testing best practices

4. **[Architecture Deep Dive](architecture.md)**
   - Technical architecture details
   - Service interaction patterns
   - Database design and schemas

5. **[API Development](api-development.md)**
   - Creating new API endpoints
   - Authentication and authorization
   - API documentation standards

## Quick Start for Developers

### 1. Set Up Development Environment

```bash
# Clone the repository
git clone https://github.com/your-org/kubenexus.git
cd kubenexus

# Set up development environment
./scripts/setup-dev-environment.sh

# Start development deployment
./scripts/dev-deploy.sh
```

### 2. Development Workflow

```bash
# Create feature branch
git checkout -b feature/your-feature-name

# Make changes and test locally
skaffold dev  # Live development with hot reload

# Run tests
./scripts/run-tests.sh

# Submit pull request
git push origin feature/your-feature-name
```

### 3. Project Structure

```
kubenexus/
├── backend/                    # Backend services
│   ├── services/              # Microservices
│   │   ├── auth-service/      # Authentication service
│   │   ├── cluster-manager/   # Cluster management
│   │   ├── sre-agent/         # SRE and ML service
│   │   └── ...
│   └── shared/                # Shared libraries
├── frontend/                  # React frontend
│   ├── src/
│   │   ├── components/        # React components
│   │   ├── pages/             # Page components
│   │   ├── services/          # API clients
│   │   └── ...
│   └── public/
├── k8s/                       # Kubernetes manifests
├── scripts/                   # Deployment scripts
├── docs/                      # Documentation
└── tests/                     # Test suites
```

## Development Stack

### Backend Technologies

- **Language**: Python 3.11+
- **Framework**: FastAPI for REST APIs
- **Database**: PostgreSQL for primary data
- **Cache**: Redis for sessions and caching
- **ML/AI**: scikit-learn for machine learning
- **Testing**: pytest for unit and integration tests
- **Async**: asyncio and asyncpg for async operations

### Frontend Technologies

- **Language**: TypeScript
- **Framework**: React 18 with hooks
- **UI Library**: Bootstrap 5
- **Build Tool**: Create React App / Vite
- **Testing**: Jest and React Testing Library
- **State Management**: React Context / Redux Toolkit

### DevOps and Infrastructure

- **Containerization**: Docker with multi-stage builds
- **Orchestration**: Kubernetes
- **Development**: Minikube with Skaffold
- **CI/CD**: GitHub Actions
- **Monitoring**: Prometheus, Grafana
- **Documentation**: Markdown with MkDocs

## Code Organization

### Backend Services Architecture

Each service follows a consistent structure:

```
service-name/
├── main.py                    # FastAPI application entry point
├── requirements.txt           # Python dependencies
├── Dockerfile                # Container build instructions
├── routers/                   # API route handlers
│   ├── __init__.py
│   ├── health.py             # Health check endpoints
│   └── service_routes.py     # Main business logic routes
├── middleware.py             # Custom middleware
├── models/                   # Pydantic data models
├── services/                 # Business logic layer
├── utils/                    # Utility functions
└── tests/                    # Service-specific tests
```

### Frontend Component Structure

```
src/
├── components/               # Reusable components
│   ├── common/              # Generic components
│   ├── layout/              # Layout components
│   └── feature-specific/    # Feature components
├── pages/                   # Page-level components
├── services/                # API service layers
├── contexts/                # React contexts
├── hooks/                   # Custom React hooks
├── types/                   # TypeScript type definitions
├── utils/                   # Utility functions
└── __tests__/               # Component tests
```

## Development Guidelines

### Code Quality Standards

- **Python**: Follow PEP 8 style guide
- **TypeScript**: Use ESLint and Prettier
- **Documentation**: Docstrings for all functions and classes
- **Type Safety**: Type hints in Python, strict TypeScript
- **Testing**: Minimum 80% code coverage

### Git Workflow

1. **Feature Branches**: Create branches from `main`
2. **Commit Messages**: Use conventional commit format
3. **Pull Requests**: Require code review and CI passes
4. **Merge Strategy**: Squash and merge for clean history

### API Design Principles

- **RESTful**: Follow REST conventions
- **Consistent**: Uniform request/response formats
- **Documented**: OpenAPI/Swagger documentation
- **Versioned**: API versioning for backward compatibility
- **Secure**: Authentication and authorization on all endpoints

## Development Tools

### Required Tools

- **Docker**: Container development
- **kubectl**: Kubernetes CLI
- **minikube**: Local Kubernetes cluster
- **skaffold**: Development workflow automation
- **Python 3.11+**: Backend development
- **Node.js 18+**: Frontend development

### Recommended IDEs

- **VS Code**: With Python, TypeScript, Docker extensions
- **PyCharm**: Professional Python IDE
- **WebStorm**: JavaScript/TypeScript IDE

### Useful VS Code Extensions

```json
{
  "recommendations": [
    "ms-python.python",
    "ms-python.flake8",
    "ms-python.black-formatter",
    "bradlc.vscode-tailwindcss",
    "ms-vscode.vscode-typescript-next",
    "esbenp.prettier-vscode",
    "ms-kubernetes-tools.vscode-kubernetes-tools",
    "ms-vscode-remote.remote-containers"
  ]
}
```

## Testing Strategy

### Backend Testing

- **Unit Tests**: pytest for individual functions/classes
- **Integration Tests**: Test service interactions
- **API Tests**: Test HTTP endpoints
- **Database Tests**: Test data layer operations

### Frontend Testing

- **Unit Tests**: Jest for individual components
- **Integration Tests**: React Testing Library
- **E2E Tests**: Cypress for user workflows
- **Visual Tests**: Storybook for component documentation

### Testing Commands

```bash
# Run all tests
./scripts/run-tests.sh

# Backend tests only
cd backend && python -m pytest

# Frontend tests only
cd frontend && npm test

# End-to-end tests
npm run test:e2e

# Coverage report
./scripts/coverage-report.sh
```

## Debugging and Troubleshooting

### Local Development Debugging

```bash
# View service logs
kubectl logs -f deployment/auth-service -n kubenexus-dev

# Port forward for direct access
kubectl port-forward service/auth-service 8001:8001 -n kubenexus-dev

# Access development database
kubectl port-forward service/postgres-service 5432:5432 -n kubenexus-dev

# Interactive debugging with pdb
# Add: import pdb; pdb.set_trace() in Python code
```

### Common Development Issues

1. **Port Conflicts**: Check for conflicting local services
2. **Database Connections**: Verify PostgreSQL is running
3. **Authentication Issues**: Check JWT token configuration
4. **Build Failures**: Clear Docker build cache
5. **Minikube Issues**: Restart minikube cluster

## Performance Considerations

### Backend Performance

- **Async/Await**: Use async patterns for I/O operations
- **Database**: Optimize queries and use indexes
- **Caching**: Implement Redis caching for expensive operations
- **Connection Pooling**: Configure database connection pools

### Frontend Performance

- **Code Splitting**: Lazy load components and routes
- **Memoization**: Use React.memo and useMemo
- **Bundle Optimization**: Analyze and optimize bundle size
- **API Optimization**: Implement proper data fetching patterns

## Security in Development

### Backend Security

- **Input Validation**: Validate all inputs with Pydantic
- **SQL Injection**: Use parameterized queries
- **CORS**: Configure CORS properly
- **Rate Limiting**: Implement rate limiting for APIs

### Frontend Security

- **XSS Prevention**: Sanitize user inputs
- **CSRF Protection**: Use proper CSRF tokens
- **Secure Storage**: Use secure storage for sensitive data
- **Authentication**: Implement proper token handling

## Contribution Workflow

### Before Contributing

1. Read the [Contributing Guidelines](contributing.md)
2. Check existing issues and pull requests
3. Set up development environment
4. Understand the codebase architecture

### Making Contributions

1. **Fork and Clone**: Fork the repository and clone locally
2. **Create Branch**: Create a feature or bug fix branch
3. **Develop**: Make changes following coding standards
4. **Test**: Ensure all tests pass and add new tests
5. **Document**: Update documentation as needed
6. **Submit PR**: Create pull request with clear description

### Review Process

1. **Automated Checks**: CI/CD pipeline runs tests
2. **Code Review**: Team members review code
3. **Feedback**: Address review comments
4. **Approval**: Maintainer approval required
5. **Merge**: Squash and merge to main branch

## Community and Support

### Getting Help

- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: GitHub Discussions for questions
- **Discord**: Real-time community chat
- **Documentation**: Comprehensive docs and guides

### Contributing to Community

- **Answer Questions**: Help other developers
- **Write Documentation**: Improve guides and tutorials
- **Report Bugs**: Help identify and fix issues
- **Suggest Features**: Propose new functionality

### Development Resources

- **Architecture Docs**: Technical design documents
- **API Reference**: Complete API documentation
- **Code Examples**: Sample implementations
- **Best Practices**: Development guidelines and patterns

---

**Ready to Start?** Check out the [Development Setup Guide](setup.md) to get your environment ready, or dive into the [Contributing Guidelines](contributing.md) to learn about our development process.

**Questions?** Join our developer community on Discord or start a discussion on GitHub! 