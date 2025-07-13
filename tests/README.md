# KubeNexus Testing Infrastructure

This directory contains the complete testing infrastructure for the KubeNexus platform, including unit tests, integration tests, and end-to-end tests.

## Test Structure

```
tests/
├── README.md                    # This file
├── conftest.py                  # Pytest configuration and fixtures
├── requirements.txt             # Testing dependencies
├── unit/                        # Unit tests
│   ├── backend/                 # Backend service unit tests
│   │   ├── auth/               # Auth service tests
│   │   ├── cluster_manager/    # Cluster manager tests
│   │   ├── sre_agent/          # SRE agent tests
│   │   └── shared/             # Shared library tests
│   └── frontend/               # Frontend unit tests (Jest)
├── integration/                # Integration tests
│   ├── api/                    # API integration tests
│   ├── database/               # Database integration tests
│   └── services/               # Service-to-service tests
├── e2e/                        # End-to-end tests
│   ├── cypress/                # Cypress E2E tests
│   └── playwright/             # Playwright E2E tests (alternative)
├── performance/                # Performance and load tests
│   ├── locust/                 # Load testing with Locust
│   └── k6/                     # Performance tests with k6
├── fixtures/                   # Test data and fixtures
│   ├── data/                   # Sample data files
│   ├── configs/                # Test configurations
│   └── mocks/                  # Mock data and responses
└── utils/                      # Testing utilities
    ├── helpers.py              # Test helper functions
    ├── factories.py            # Data factories
    └── docker_utils.py         # Docker test utilities
```

## Testing Strategy

### Unit Tests
- **Coverage Target**: 80% minimum
- **Framework**: pytest (Backend), Jest (Frontend)
- **Scope**: Individual functions, classes, and components
- **Isolation**: Mocked dependencies

### Integration Tests
- **Framework**: pytest with testcontainers
- **Scope**: Service interactions, database operations, API endpoints
- **Environment**: Docker containers for dependencies

### End-to-End Tests
- **Framework**: Cypress (primary), Playwright (alternative)
- **Scope**: Complete user workflows and scenarios
- **Environment**: Full application stack

### Performance Tests
- **Framework**: Locust for load testing, k6 for performance
- **Scope**: API performance, database load, concurrent users
- **Metrics**: Response time, throughput, resource usage

## Quick Start

### Prerequisites

```bash
# Install Python testing dependencies
pip install -r tests/requirements.txt

# Install Node.js testing dependencies (for frontend)
cd frontend && npm install

# Install additional tools
npm install -g cypress @playwright/test
```

### Running Tests

```bash
# All tests
./scripts/run-tests.sh

# Backend unit tests only
pytest tests/unit/backend/

# Frontend unit tests only
cd frontend && npm test

# Integration tests (requires Docker)
pytest tests/integration/

# E2E tests (requires running application)
npx cypress run

# Performance tests
cd tests/performance/locust && locust
```

### Test Configuration

Tests can be configured via environment variables:

```bash
# Test database URL
export TEST_DATABASE_URL="postgresql://test:test@localhost:5433/test"

# Test Redis URL
export TEST_REDIS_URL="redis://localhost:6380/0"

# Application URL for E2E tests
export E2E_BASE_URL="http://localhost:3000"

# Test environment
export TEST_ENV="local"
```

## Test Categories

### Backend Tests

#### Unit Tests (`tests/unit/backend/`)
- Service layer logic
- Data model validation
- Utility functions
- Authentication/authorization logic

#### Integration Tests (`tests/integration/`)
- API endpoint testing
- Database operations
- External service integrations
- Message queue operations

### Frontend Tests

#### Unit Tests (`frontend/src/__tests__/`)
- Component rendering
- Hook functionality
- Utility functions
- State management

#### Integration Tests
- API service integration
- Form submissions
- Navigation flows
- Error handling

### End-to-End Tests

#### User Workflows (`tests/e2e/`)
- User registration and login
- Cluster management operations
- Monitoring and alerting
- SRE agent interactions
- Terminal sessions

### Performance Tests

#### Load Testing (`tests/performance/`)
- API endpoint performance
- Database query performance
- Concurrent user scenarios
- Resource utilization

## Test Data Management

### Fixtures and Factories

```python
# Example: User factory
from factory import Factory, Faker
from models import User

class UserFactory(Factory):
    class Meta:
        model = User
    
    username = Faker('user_name')
    email = Faker('email')
    full_name = Faker('name')
    is_active = True
```

### Database Seeding

```python
# Test database setup
def setup_test_data():
    """Set up test data for integration tests."""
    # Create test users
    admin_user = UserFactory(is_admin=True)
    regular_user = UserFactory()
    
    # Create test clusters
    cluster = ClusterFactory(created_by=admin_user)
    
    return {
        'admin_user': admin_user,
        'regular_user': regular_user,
        'cluster': cluster
    }
```

## Testing Guidelines

### Best Practices

1. **Test Naming**: Use descriptive test names that explain what is being tested
2. **Isolation**: Each test should be independent and not rely on other tests
3. **Data**: Use factories and fixtures for test data generation
4. **Mocking**: Mock external dependencies to ensure test reliability
5. **Assertions**: Use specific assertions that clearly indicate what failed

### Code Coverage

```bash
# Generate coverage report for backend
pytest --cov=backend --cov-report=html tests/unit/backend/

# Generate coverage report for frontend
cd frontend && npm run test:coverage
```

Coverage thresholds:
- **Unit Tests**: 80% minimum
- **Integration Tests**: 70% minimum
- **Overall Coverage**: 75% minimum

### Continuous Integration

Tests are automatically run on:
- Pull request creation/updates
- Push to main branch
- Nightly builds for performance regression testing

CI Pipeline stages:
1. **Lint and Format Check**
2. **Unit Tests** (parallel execution)
3. **Integration Tests** (with test containers)
4. **Security Scans**
5. **Build and Deploy to Staging**
6. **E2E Tests** (against staging)
7. **Performance Tests** (nightly)

## Test Environments

### Local Development
- Use testcontainers for databases
- Mock external services
- Fast feedback loop

### CI/CD Pipeline
- Isolated test environments
- Real service dependencies
- Comprehensive test suite

### Staging Environment
- Full application stack
- Production-like data
- E2E and performance testing

## Debugging Tests

### Common Issues

1. **Flaky Tests**: Use proper waits and retries
2. **Database State**: Ensure proper cleanup between tests
3. **Async Operations**: Use appropriate async/await patterns
4. **Timeouts**: Configure appropriate timeouts for different test types

### Debugging Tools

```bash
# Run specific test with verbose output
pytest -v -s tests/unit/backend/auth/test_auth_service.py::test_login

# Debug frontend tests
cd frontend && npm test -- --watchAll --verbose

# Debug E2E tests with browser open
npx cypress open

# Profile performance tests
cd tests/performance && locust --web-port 8090
```

## Contributing to Tests

### Adding New Tests

1. **Backend Tests**: Add to appropriate service directory in `tests/unit/backend/`
2. **Frontend Tests**: Add alongside components in `frontend/src/__tests__/`
3. **Integration Tests**: Add to `tests/integration/` with proper setup/teardown
4. **E2E Tests**: Add to `tests/e2e/` with user scenario focus

### Test Review Checklist

- [ ] Test is properly isolated
- [ ] Test data is generated using factories
- [ ] External dependencies are mocked
- [ ] Test has clear assertions
- [ ] Test follows naming conventions
- [ ] Test includes both positive and negative cases
- [ ] Test has appropriate timeout settings

## Resources

### Documentation
- [pytest Documentation](https://docs.pytest.org/)
- [Jest Documentation](https://jestjs.io/docs/getting-started)
- [Cypress Documentation](https://docs.cypress.io/)
- [Locust Documentation](https://locust.io/)

### Tools and Libraries
- **pytest**: Python testing framework
- **testcontainers**: Integration testing with Docker
- **factory-boy**: Test data generation
- **Jest**: JavaScript testing framework
- **Cypress**: E2E testing framework
- **Locust**: Load testing framework

---

**Need Help?**
- Check the test documentation in each directory
- Review existing tests for examples
- Ask in the development team Slack channel
- Create an issue for test infrastructure improvements 