"""Data factories for generating test data using factory_boy."""

import factory
from factory import Faker, SubFactory, LazyAttribute
from datetime import datetime, timedelta
import uuid
import base64
import json

# Import your models
from backend.shared.models import (
    User, Role, UserRole, Cluster, AuditLog, 
    SREProblem, SRERecommendation, ClusterMetrics,
    UserSession, APIKey
)


class UserFactory(factory.Factory):
    """Factory for creating User instances."""
    
    class Meta:
        model = User
    
    username = Faker('user_name')
    email = Faker('email')
    password_hash = factory.LazyFunction(
        lambda: '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6jJA7kOHtq'  # "admin123!"
    )
    full_name = Faker('name')
    is_active = True
    is_admin = False
    created_at = factory.LazyFunction(datetime.utcnow)
    updated_at = factory.LazyFunction(datetime.utcnow)
    failed_login_attempts = 0


class AdminUserFactory(UserFactory):
    """Factory for creating admin User instances."""
    
    username = "admin"
    email = "admin@test.com"
    is_admin = True


class RoleFactory(factory.Factory):
    """Factory for creating Role instances."""
    
    class Meta:
        model = Role
    
    name = Faker('word')
    description = Faker('sentence')
    permissions = factory.LazyFunction(
        lambda: {
            "clusters": ["read", "write"],
            "monitoring": ["read"],
            "users": ["read"]
        }
    )
    created_at = factory.LazyFunction(datetime.utcnow)


class AdminRoleFactory(RoleFactory):
    """Factory for creating admin Role instances."""
    
    name = "admin"
    description = "Full system access"
    permissions = factory.LazyFunction(lambda: {"all": True})


class UserRoleFactory(factory.Factory):
    """Factory for creating UserRole instances."""
    
    class Meta:
        model = UserRole
    
    user = SubFactory(UserFactory)
    role = SubFactory(RoleFactory)
    assigned_at = factory.LazyFunction(datetime.utcnow)


class ClusterFactory(factory.Factory):
    """Factory for creating Cluster instances."""
    
    class Meta:
        model = Cluster
    
    name = Faker('word')
    description = Faker('sentence')
    provider = Faker('random_element', elements=['aws', 'gcp', 'azure', 'local'])
    region = Faker('random_element', elements=['us-west-2', 'us-east-1', 'eu-west-1'])
    version = Faker('random_element', elements=['1.24.0', '1.25.0', '1.26.0'])
    status = Faker('random_element', elements=['active', 'pending', 'error', 'deleting'])
    kubeconfig_encrypted = LazyAttribute(
        lambda obj: base64.b64encode(
            json.dumps({
                "apiVersion": "v1",
                "kind": "Config",
                "clusters": [{
                    "cluster": {
                        "server": f"https://{obj.name}.example.com"
                    },
                    "name": obj.name
                }],
                "contexts": [{
                    "context": {
                        "cluster": obj.name,
                        "user": "test-user"
                    },
                    "name": f"{obj.name}-context"
                }],
                "current-context": f"{obj.name}-context",
                "users": [{
                    "name": "test-user",
                    "user": {"token": "test-token"}
                }]
            }).encode()
        ).decode()
    )
    endpoint_url = LazyAttribute(lambda obj: f"https://{obj.name}.example.com")
    created_by = SubFactory(UserFactory)
    created_at = factory.LazyFunction(datetime.utcnow)
    updated_at = factory.LazyFunction(datetime.utcnow)
    metadata = factory.LazyFunction(
        lambda: {
            "nodeCount": 3,
            "region": "us-west-2",
            "tags": {"environment": "test"}
        }
    )


class AuditLogFactory(factory.Factory):
    """Factory for creating AuditLog instances."""
    
    class Meta:
        model = AuditLog
    
    user = SubFactory(UserFactory)
    action = Faker('random_element', elements=[
        'login', 'logout', 'create_cluster', 'delete_cluster',
        'update_user', 'create_role', 'assign_role'
    ])
    resource_type = Faker('random_element', elements=[
        'user', 'cluster', 'role', 'api_key', 'session'
    ])
    resource_id = factory.LazyFunction(lambda: str(uuid.uuid4()))
    details = factory.LazyFunction(
        lambda: {
            "method": "POST",
            "endpoint": "/api/clusters",
            "status_code": 201
        }
    )
    ip_address = Faker('ipv4')
    user_agent = Faker('user_agent')
    timestamp = factory.LazyFunction(datetime.utcnow)
    success = True


class SREProblemFactory(factory.Factory):
    """Factory for creating SREProblem instances."""
    
    class Meta:
        model = SREProblem
    
    cluster = SubFactory(ClusterFactory)
    title = Faker('sentence', nb_words=4)
    description = Faker('text')
    severity = Faker('random_element', elements=['low', 'medium', 'high', 'critical'])
    status = Faker('random_element', elements=['open', 'investigating', 'resolved', 'closed'])
    category = Faker('random_element', elements=[
        'performance', 'availability', 'security', 'resource', 'network'
    ])
    detected_at = factory.LazyFunction(datetime.utcnow)
    assigned_to = SubFactory(UserFactory)
    metadata = factory.LazyFunction(
        lambda: {
            "source": "anomaly_detection",
            "confidence": 0.85,
            "affected_resources": ["deployment/app", "service/app"]
        }
    )


class SRERecommendationFactory(factory.Factory):
    """Factory for creating SRERecommendation instances."""
    
    class Meta:
        model = SRERecommendation
    
    cluster = SubFactory(ClusterFactory)
    problem = SubFactory(SREProblemFactory)
    title = Faker('sentence', nb_words=4)
    description = Faker('text')
    category = Faker('random_element', elements=[
        'optimization', 'scaling', 'security', 'maintenance'
    ])
    priority = Faker('random_element', elements=['low', 'medium', 'high'])
    confidence_score = Faker('pydecimal', left_digits=1, right_digits=2, min_value=0.1, max_value=1.0)
    implementation_steps = factory.LazyFunction(
        lambda: [
            "Step 1: Analyze current resource usage",
            "Step 2: Implement horizontal pod autoscaler",
            "Step 3: Monitor performance improvements"
        ]
    )
    created_at = factory.LazyFunction(datetime.utcnow)
    implemented = False
    feedback_rating = None


class ClusterMetricsFactory(factory.Factory):
    """Factory for creating ClusterMetrics instances."""
    
    class Meta:
        model = ClusterMetrics
    
    cluster = SubFactory(ClusterFactory)
    metric_name = Faker('random_element', elements=[
        'cpu_usage', 'memory_usage', 'disk_usage', 'network_io',
        'pod_count', 'node_count', 'request_rate', 'error_rate'
    ])
    metric_value = Faker('pydecimal', left_digits=3, right_digits=2, min_value=0, max_value=100)
    metric_unit = LazyAttribute(
        lambda obj: {
            'cpu_usage': 'percent',
            'memory_usage': 'percent',
            'disk_usage': 'percent',
            'network_io': 'mbps',
            'pod_count': 'count',
            'node_count': 'count',
            'request_rate': 'req/sec',
            'error_rate': 'percent'
        }.get(obj.metric_name, 'count')
    )
    collected_at = factory.LazyFunction(datetime.utcnow)
    metadata = factory.LazyFunction(
        lambda: {
            "collector": "prometheus",
            "namespace": "default",
            "labels": {"app": "test"}
        }
    )


class UserSessionFactory(factory.Factory):
    """Factory for creating UserSession instances."""
    
    class Meta:
        model = UserSession
    
    id = factory.LazyFunction(lambda: str(uuid.uuid4()))
    user = SubFactory(UserFactory)
    created_at = factory.LazyFunction(datetime.utcnow)
    expires_at = factory.LazyFunction(lambda: datetime.utcnow() + timedelta(hours=24))
    ip_address = Faker('ipv4')
    user_agent = Faker('user_agent')
    is_active = True


class APIKeyFactory(factory.Factory):
    """Factory for creating APIKey instances."""
    
    class Meta:
        model = APIKey
    
    user = SubFactory(UserFactory)
    name = Faker('word')
    key_hash = factory.LazyFunction(
        lambda: '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6jJA7kOHtq'
    )
    key_prefix = factory.LazyFunction(lambda: f"kn_{uuid.uuid4().hex[:8]}")
    permissions = factory.LazyFunction(
        lambda: {
            "clusters": ["read"],
            "monitoring": ["read"]
        }
    )
    expires_at = factory.LazyFunction(lambda: datetime.utcnow() + timedelta(days=365))
    created_at = factory.LazyFunction(datetime.utcnow)
    is_active = True


# Specialized factories for specific test scenarios

class ProductionClusterFactory(ClusterFactory):
    """Factory for production-like clusters."""
    
    name = factory.Sequence(lambda n: f"prod-cluster-{n}")
    provider = "aws"
    region = "us-west-2"
    status = "active"
    version = "1.26.0"
    metadata = factory.LazyFunction(
        lambda: {
            "nodeCount": 10,
            "instanceType": "m5.xlarge",
            "region": "us-west-2",
            "tags": {
                "environment": "production",
                "team": "platform"
            }
        }
    )


class DevelopmentClusterFactory(ClusterFactory):
    """Factory for development clusters."""
    
    name = factory.Sequence(lambda n: f"dev-cluster-{n}")
    provider = "local"
    region = "local"
    status = "active"
    version = "1.24.0"
    metadata = factory.LazyFunction(
        lambda: {
            "nodeCount": 1,
            "instanceType": "local",
            "region": "local",
            "tags": {
                "environment": "development",
                "team": "dev"
            }
        }
    )


class CriticalSREProblemFactory(SREProblemFactory):
    """Factory for critical SRE problems."""
    
    severity = "critical"
    status = "open"
    category = "availability"
    title = "Critical service outage detected"
    metadata = factory.LazyFunction(
        lambda: {
            "source": "anomaly_detection",
            "confidence": 0.95,
            "affected_resources": ["deployment/critical-app"],
            "impact": "service_unavailable"
        }
    )


class HighValueRecommendationFactory(SRERecommendationFactory):
    """Factory for high-value recommendations."""
    
    priority = "high"
    confidence_score = factory.LazyFunction(lambda: round(0.9 + (0.1 * factory.Faker('random').generate({})), 2))
    category = "optimization"
    implemented = False


# Batch creation helpers

def create_test_environment(db_session):
    """Create a complete test environment with all related objects."""
    # Create users and roles
    admin_role = AdminRoleFactory()
    user_role = RoleFactory(name="user", description="Standard user access")
    
    admin_user = AdminUserFactory()
    regular_user = UserFactory()
    
    # Assign roles
    admin_user_role = UserRoleFactory(user=admin_user, role=admin_role)
    regular_user_role = UserRoleFactory(user=regular_user, role=user_role)
    
    # Create clusters
    prod_cluster = ProductionClusterFactory(created_by=admin_user)
    dev_cluster = DevelopmentClusterFactory(created_by=regular_user)
    
    # Create SRE data
    problem = CriticalSREProblemFactory(cluster=prod_cluster, assigned_to=admin_user)
    recommendation = HighValueRecommendationFactory(cluster=prod_cluster, problem=problem)
    
    # Create metrics
    metrics = [
        ClusterMetricsFactory(cluster=prod_cluster, metric_name="cpu_usage", metric_value=75.5),
        ClusterMetricsFactory(cluster=prod_cluster, metric_name="memory_usage", metric_value=82.3),
        ClusterMetricsFactory(cluster=dev_cluster, metric_name="cpu_usage", metric_value=25.1),
    ]
    
    # Create audit logs
    audit_logs = [
        AuditLogFactory(user=admin_user, action="create_cluster", resource_type="cluster", resource_id=str(prod_cluster.id)),
        AuditLogFactory(user=regular_user, action="login", resource_type="session"),
    ]
    
    # Add all to session
    objects = [
        admin_role, user_role, admin_user, regular_user,
        admin_user_role, regular_user_role, prod_cluster, dev_cluster,
        problem, recommendation
    ] + metrics + audit_logs
    
    for obj in objects:
        db_session.add(obj)
    
    db_session.commit()
    
    return {
        'admin_user': admin_user,
        'regular_user': regular_user,
        'admin_role': admin_role,
        'user_role': user_role,
        'prod_cluster': prod_cluster,
        'dev_cluster': dev_cluster,
        'problem': problem,
        'recommendation': recommendation,
        'metrics': metrics,
        'audit_logs': audit_logs
    } 