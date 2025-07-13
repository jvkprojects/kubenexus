"""Pytest configuration and shared fixtures for KubeNexus tests."""

import asyncio
import os
import tempfile
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from testcontainers.postgres import PostgresContainer
from testcontainers.redis import RedisContainer

# Import your application modules
from backend.shared.database import Base, get_db
from backend.shared.config import Settings


# Test configuration
@pytest.fixture(scope="session")
def test_settings():
    """Test application settings."""
    return Settings(
        database_url="postgresql://test:test@localhost:5433/test",
        redis_url="redis://localhost:6380/0",
        jwt_secret_key="test-secret-key",
        encryption_key="test-encryption-key",
        environment="test",
        log_level="DEBUG"
    )


# Database fixtures
@pytest.fixture(scope="session")
def postgres_container():
    """PostgreSQL container for integration tests."""
    with PostgresContainer("postgres:15") as postgres:
        yield postgres


@pytest.fixture(scope="session")
def redis_container():
    """Redis container for integration tests."""
    with RedisContainer("redis:7-alpine") as redis:
        yield redis


@pytest.fixture(scope="session")
def test_db_engine(postgres_container):
    """Test database engine."""
    db_url = postgres_container.get_connection_url()
    engine = create_engine(db_url)
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    yield engine
    
    # Cleanup
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def test_db_session(test_db_engine):
    """Test database session with transaction rollback."""
    connection = test_db_engine.connect()
    transaction = connection.begin()
    
    # Create session
    SessionLocal = sessionmaker(bind=connection)
    session = SessionLocal()
    
    yield session
    
    # Rollback transaction and close connection
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def test_redis_client(redis_container):
    """Test Redis client."""
    import redis
    
    redis_url = redis_container.get_connection_url()
    client = redis.from_url(redis_url)
    
    yield client
    
    # Cleanup
    client.flushall()
    client.close()


# HTTP client fixtures
@pytest.fixture
def test_client(test_db_session, test_redis_client, test_settings):
    """Test HTTP client with dependency overrides."""
    from backend.services.api_gateway.main import app
    
    def override_get_db():
        yield test_db_session
    
    def override_get_redis():
        return test_redis_client
    
    def override_get_settings():
        return test_settings
    
    app.dependency_overrides[get_db] = override_get_db
    # Add other dependency overrides as needed
    
    with TestClient(app) as client:
        yield client
    
    # Clean up overrides
    app.dependency_overrides.clear()


# Authentication fixtures
@pytest.fixture
def admin_user(test_db_session):
    """Create admin user for testing."""
    from tests.utils.factories import UserFactory
    
    user = UserFactory(
        username="admin",
        email="admin@test.com",
        is_admin=True,
        is_active=True
    )
    test_db_session.add(user)
    test_db_session.commit()
    test_db_session.refresh(user)
    
    return user


@pytest.fixture
def regular_user(test_db_session):
    """Create regular user for testing."""
    from tests.utils.factories import UserFactory
    
    user = UserFactory(
        username="user",
        email="user@test.com",
        is_admin=False,
        is_active=True
    )
    test_db_session.add(user)
    test_db_session.commit()
    test_db_session.refresh(user)
    
    return user


@pytest.fixture
def auth_headers(admin_user, test_client):
    """Authentication headers for API testing."""
    from backend.shared.auth import create_access_token
    
    token = create_access_token(data={"sub": admin_user.username})
    return {"Authorization": f"Bearer {token}"}


# Mock fixtures
@pytest.fixture
def mock_kubernetes_client():
    """Mock Kubernetes client."""
    mock_client = MagicMock()
    mock_client.list_namespaced_pod = MagicMock(return_value=MagicMock())
    mock_client.create_namespaced_deployment = MagicMock()
    mock_client.delete_namespaced_deployment = MagicMock()
    
    return mock_client


@pytest.fixture
def mock_redis():
    """Mock Redis client."""
    mock_redis = MagicMock()
    mock_redis.get = MagicMock(return_value=None)
    mock_redis.set = MagicMock(return_value=True)
    mock_redis.delete = MagicMock(return_value=1)
    mock_redis.exists = MagicMock(return_value=False)
    
    return mock_redis


@pytest.fixture
def mock_external_api():
    """Mock external API responses."""
    import responses
    
    with responses.RequestsMock() as rsps:
        # Mock common external API calls
        rsps.add(
            responses.GET,
            "https://api.external-service.com/health",
            json={"status": "ok"},
            status=200
        )
        
        yield rsps


# Cluster fixtures
@pytest.fixture
def test_cluster(test_db_session, admin_user):
    """Create test cluster."""
    from tests.utils.factories import ClusterFactory
    
    cluster = ClusterFactory(
        name="test-cluster",
        description="Test cluster for integration tests",
        provider="test",
        region="test-region",
        created_by=admin_user.id
    )
    test_db_session.add(cluster)
    test_db_session.commit()
    test_db_session.refresh(cluster)
    
    return cluster


# File fixtures
@pytest.fixture
def temp_kubeconfig():
    """Temporary kubeconfig file for testing."""
    kubeconfig_content = """
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://test-cluster.example.com
  name: test-cluster
contexts:
- context:
    cluster: test-cluster
    user: test-user
  name: test-context
current-context: test-context
users:
- name: test-user
  user:
    token: test-token
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(kubeconfig_content)
        f.flush()
        
        yield f.name
    
    # Cleanup
    os.unlink(f.name)


# Async fixtures
@pytest_asyncio.fixture
async def async_test_client():
    """Async test client for testing async endpoints."""
    from httpx import AsyncClient
    from backend.services.api_gateway.main import app
    
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


@pytest_asyncio.fixture
async def async_db_session():
    """Async database session for testing."""
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    async with AsyncSession(engine) as session:
        yield session
    
    await engine.dispose()


# Performance testing fixtures
@pytest.fixture
def performance_test_data():
    """Data for performance testing."""
    return {
        "users": 100,
        "clusters": 50,
        "metrics": 1000,
        "duration": 60  # seconds
    }


# WebSocket fixtures
@pytest.fixture
def websocket_test_client():
    """WebSocket test client."""
    from fastapi.testclient import TestClient
    from backend.services.terminal_service.main import app
    
    client = TestClient(app)
    return client


# Event loop for async tests
@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# Markers for different test types
def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "e2e: mark test as an end-to-end test"
    )
    config.addinivalue_line(
        "markers", "performance: mark test as a performance test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )


# Skip markers based on environment
def pytest_collection_modifyitems(config, items):
    """Modify test collection based on environment."""
    if config.getoption("--integration-only"):
        skip_unit = pytest.mark.skip(reason="--integration-only option provided")
        for item in items:
            if "integration" not in item.keywords:
                item.add_marker(skip_unit)
    
    if config.getoption("--unit-only"):
        skip_integration = pytest.mark.skip(reason="--unit-only option provided")
        for item in items:
            if "unit" not in item.keywords:
                item.add_marker(skip_integration)


def pytest_addoption(parser):
    """Add custom command line options."""
    parser.addoption(
        "--integration-only",
        action="store_true",
        default=False,
        help="run integration tests only"
    )
    parser.addoption(
        "--unit-only",
        action="store_true",
        default=False,
        help="run unit tests only"
    )
    parser.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="run slow tests"
    )


# Cleanup fixtures
@pytest.fixture(autouse=True)
def cleanup_test_files():
    """Automatically cleanup test files after each test."""
    test_files = []
    
    yield test_files
    
    # Cleanup any created test files
    for file_path in test_files:
        if os.path.exists(file_path):
            os.unlink(file_path) 