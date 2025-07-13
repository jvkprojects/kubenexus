"""Integration tests for cluster management API."""

import pytest
import json
import base64
from unittest.mock import patch, MagicMock
from datetime import datetime

from tests.utils.factories import ClusterFactory, UserFactory, AdminUserFactory


@pytest.mark.integration
class TestClusterManagementAPI:
    """Integration tests for cluster management endpoints."""
    
    def test_create_cluster_success(self, test_client, auth_headers, test_db_session):
        """Test successful cluster creation."""
        cluster_data = {
            "name": "test-cluster",
            "description": "Test cluster for integration testing",
            "provider": "aws",
            "region": "us-west-2",
            "kubeconfig": base64.b64encode(json.dumps({
                "apiVersion": "v1",
                "kind": "Config",
                "clusters": [{
                    "cluster": {"server": "https://test-cluster.example.com"},
                    "name": "test-cluster"
                }],
                "contexts": [{
                    "context": {"cluster": "test-cluster", "user": "test-user"},
                    "name": "test-context"
                }],
                "current-context": "test-context",
                "users": [{
                    "name": "test-user",
                    "user": {"token": "test-token"}
                }]
            }).encode()).decode()
        }
        
        with patch('backend.services.cluster_manager_service.routers.clusters.validate_kubeconfig') as mock_validate:
            mock_validate.return_value = True
            
            response = test_client.post("/api/clusters", json=cluster_data, headers=auth_headers)
            
            assert response.status_code == 201
            data = response.json()
            assert data["status"] == "success"
            assert data["data"]["name"] == "test-cluster"
            assert data["data"]["provider"] == "aws"
            assert data["data"]["region"] == "us-west-2"
            assert data["data"]["status"] == "pending"
    
    def test_create_cluster_invalid_kubeconfig(self, test_client, auth_headers):
        """Test cluster creation with invalid kubeconfig."""
        cluster_data = {
            "name": "test-cluster",
            "description": "Test cluster",
            "provider": "aws",
            "region": "us-west-2",
            "kubeconfig": "invalid-base64-content"
        }
        
        response = test_client.post("/api/clusters", json=cluster_data, headers=auth_headers)
        
        assert response.status_code == 400
        data = response.json()
        assert "error" in data
        assert "kubeconfig" in data["error"]["message"].lower()
    
    def test_create_cluster_duplicate_name(self, test_client, auth_headers, test_db_session, admin_user):
        """Test cluster creation with duplicate name."""
        # Create existing cluster
        existing_cluster = ClusterFactory(name="duplicate-cluster", created_by=admin_user.id)
        test_db_session.add(existing_cluster)
        test_db_session.commit()
        
        cluster_data = {
            "name": "duplicate-cluster",
            "description": "Duplicate cluster name",
            "provider": "aws",
            "region": "us-west-2",
            "kubeconfig": base64.b64encode(b"test-config").decode()
        }
        
        response = test_client.post("/api/clusters", json=cluster_data, headers=auth_headers)
        
        assert response.status_code == 409
        data = response.json()
        assert "error" in data
        assert "already exists" in data["error"]["message"]
    
    def test_list_clusters_success(self, test_client, auth_headers, test_db_session, admin_user):
        """Test successful cluster listing."""
        # Create test clusters
        clusters = [
            ClusterFactory(name=f"cluster-{i}", created_by=admin_user.id)
            for i in range(3)
        ]
        for cluster in clusters:
            test_db_session.add(cluster)
        test_db_session.commit()
        
        response = test_client.get("/api/clusters", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert len(data["data"]) >= 3
        assert "pagination" in data
    
    def test_list_clusters_with_filters(self, test_client, auth_headers, test_db_session, admin_user):
        """Test cluster listing with filters."""
        # Create clusters with different providers
        aws_cluster = ClusterFactory(name="aws-cluster", provider="aws", created_by=admin_user.id)
        gcp_cluster = ClusterFactory(name="gcp-cluster", provider="gcp", created_by=admin_user.id)
        
        test_db_session.add(aws_cluster)
        test_db_session.add(gcp_cluster)
        test_db_session.commit()
        
        # Filter by provider
        response = test_client.get("/api/clusters?provider=aws", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        
        # Should only return AWS clusters
        for cluster in data["data"]:
            assert cluster["provider"] == "aws"
    
    def test_get_cluster_by_id_success(self, test_client, auth_headers, test_db_session, admin_user):
        """Test getting cluster by ID."""
        cluster = ClusterFactory(name="get-cluster", created_by=admin_user.id)
        test_db_session.add(cluster)
        test_db_session.commit()
        
        response = test_client.get(f"/api/clusters/{cluster.id}", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["data"]["id"] == cluster.id
        assert data["data"]["name"] == "get-cluster"
    
    def test_get_cluster_not_found(self, test_client, auth_headers):
        """Test getting non-existent cluster."""
        response = test_client.get("/api/clusters/99999", headers=auth_headers)
        
        assert response.status_code == 404
        data = response.json()
        assert "error" in data
    
    def test_update_cluster_success(self, test_client, auth_headers, test_db_session, admin_user):
        """Test successful cluster update."""
        cluster = ClusterFactory(name="update-cluster", description="Old description", created_by=admin_user.id)
        test_db_session.add(cluster)
        test_db_session.commit()
        
        update_data = {
            "description": "Updated description",
            "metadata": {"updated": True}
        }
        
        response = test_client.patch(f"/api/clusters/{cluster.id}", json=update_data, headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["data"]["description"] == "Updated description"
        assert data["data"]["metadata"]["updated"] is True
    
    def test_delete_cluster_success(self, test_client, auth_headers, test_db_session, admin_user):
        """Test successful cluster deletion."""
        cluster = ClusterFactory(name="delete-cluster", created_by=admin_user.id)
        test_db_session.add(cluster)
        test_db_session.commit()
        
        with patch('backend.services.cluster_manager_service.routers.clusters.cleanup_cluster_resources') as mock_cleanup:
            mock_cleanup.return_value = True
            
            response = test_client.delete(f"/api/clusters/{cluster.id}", headers=auth_headers)
            
            assert response.status_code == 204
            mock_cleanup.assert_called_once()
    
    def test_cluster_health_check(self, test_client, auth_headers, test_db_session, admin_user):
        """Test cluster health check endpoint."""
        cluster = ClusterFactory(name="health-cluster", status="active", created_by=admin_user.id)
        test_db_session.add(cluster)
        test_db_session.commit()
        
        with patch('backend.services.cluster_manager_service.routers.clusters.check_cluster_health') as mock_health:
            mock_health.return_value = {
                "status": "healthy",
                "nodes": 3,
                "pods": 25,
                "services": 5
            }
            
            response = test_client.get(f"/api/clusters/{cluster.id}/health", headers=auth_headers)
            
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert data["data"]["status"] == "healthy"
            assert data["data"]["nodes"] == 3


@pytest.mark.integration
class TestClusterResourceManagement:
    """Integration tests for cluster resource management."""
    
    def test_list_cluster_namespaces(self, test_client, auth_headers, test_db_session, admin_user):
        """Test listing cluster namespaces."""
        cluster = ClusterFactory(name="namespace-cluster", created_by=admin_user.id)
        test_db_session.add(cluster)
        test_db_session.commit()
        
        with patch('backend.services.cluster_manager_service.routers.clusters.get_cluster_namespaces') as mock_namespaces:
            mock_namespaces.return_value = [
                {"name": "default", "status": "Active"},
                {"name": "kube-system", "status": "Active"},
                {"name": "my-app", "status": "Active"}
            ]
            
            response = test_client.get(f"/api/clusters/{cluster.id}/namespaces", headers=auth_headers)
            
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert len(data["data"]) == 3
            assert any(ns["name"] == "default" for ns in data["data"])
    
    def test_list_cluster_pods(self, test_client, auth_headers, test_db_session, admin_user):
        """Test listing cluster pods."""
        cluster = ClusterFactory(name="pods-cluster", created_by=admin_user.id)
        test_db_session.add(cluster)
        test_db_session.commit()
        
        with patch('backend.services.cluster_manager_service.routers.clusters.get_cluster_pods') as mock_pods:
            mock_pods.return_value = [
                {
                    "name": "app-pod-1",
                    "namespace": "default",
                    "status": "Running",
                    "ready": "1/1",
                    "restarts": 0,
                    "age": "1d"
                },
                {
                    "name": "app-pod-2",
                    "namespace": "default",
                    "status": "Running",
                    "ready": "1/1",
                    "restarts": 0,
                    "age": "1d"
                }
            ]
            
            response = test_client.get(f"/api/clusters/{cluster.id}/pods", headers=auth_headers)
            
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert len(data["data"]) == 2
            assert all(pod["status"] == "Running" for pod in data["data"])
    
    def test_list_cluster_services(self, test_client, auth_headers, test_db_session, admin_user):
        """Test listing cluster services."""
        cluster = ClusterFactory(name="services-cluster", created_by=admin_user.id)
        test_db_session.add(cluster)
        test_db_session.commit()
        
        with patch('backend.services.cluster_manager_service.routers.clusters.get_cluster_services') as mock_services:
            mock_services.return_value = [
                {
                    "name": "kubernetes",
                    "namespace": "default",
                    "type": "ClusterIP",
                    "cluster_ip": "10.96.0.1",
                    "external_ip": "<none>",
                    "ports": ["443/TCP"]
                }
            ]
            
            response = test_client.get(f"/api/clusters/{cluster.id}/services", headers=auth_headers)
            
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert len(data["data"]) >= 1
    
    def test_create_namespace(self, test_client, auth_headers, test_db_session, admin_user):
        """Test creating a namespace in cluster."""
        cluster = ClusterFactory(name="create-ns-cluster", created_by=admin_user.id)
        test_db_session.add(cluster)
        test_db_session.commit()
        
        namespace_data = {
            "name": "test-namespace",
            "labels": {"environment": "test"}
        }
        
        with patch('backend.services.cluster_manager_service.routers.clusters.create_namespace') as mock_create:
            mock_create.return_value = {"name": "test-namespace", "status": "Active"}
            
            response = test_client.post(
                f"/api/clusters/{cluster.id}/namespaces",
                json=namespace_data,
                headers=auth_headers
            )
            
            assert response.status_code == 201
            data = response.json()
            assert data["status"] == "success"
            assert data["data"]["name"] == "test-namespace"


@pytest.mark.integration 
class TestClusterPermissions:
    """Integration tests for cluster access permissions."""
    
    def test_admin_can_access_all_clusters(self, test_client, test_db_session):
        """Test that admin users can access all clusters."""
        admin_user = AdminUserFactory()
        regular_user = UserFactory()
        test_db_session.add(admin_user)
        test_db_session.add(regular_user)
        test_db_session.commit()
        
        # Create cluster owned by regular user
        cluster = ClusterFactory(name="admin-access-test", created_by=regular_user.id)
        test_db_session.add(cluster)
        test_db_session.commit()
        
        # Admin should be able to access it
        admin_token = self._create_token_for_user(admin_user)
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        
        response = test_client.get(f"/api/clusters/{cluster.id}", headers=admin_headers)
        
        assert response.status_code == 200
    
    def test_user_can_only_access_own_clusters(self, test_client, test_db_session):
        """Test that regular users can only access their own clusters."""
        user1 = UserFactory(username="user1")
        user2 = UserFactory(username="user2")
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        
        # Create cluster owned by user1
        cluster = ClusterFactory(name="user1-cluster", created_by=user1.id)
        test_db_session.add(cluster)
        test_db_session.commit()
        
        # User2 should not be able to access it
        user2_token = self._create_token_for_user(user2)
        user2_headers = {"Authorization": f"Bearer {user2_token}"}
        
        response = test_client.get(f"/api/clusters/{cluster.id}", headers=user2_headers)
        
        assert response.status_code == 403
    
    def _create_token_for_user(self, user):
        """Helper method to create JWT token for user."""
        from backend.services.auth_service.routers.auth import create_access_token
        return create_access_token(data={"sub": user.username, "admin": user.is_admin})


@pytest.mark.integration
class TestClusterKubernetesIntegration:
    """Integration tests for Kubernetes client integration."""
    
    def test_kubernetes_client_connection(self, test_client, auth_headers, test_db_session, admin_user):
        """Test Kubernetes client connection validation."""
        cluster = ClusterFactory(name="k8s-test-cluster", created_by=admin_user.id)
        test_db_session.add(cluster)
        test_db_session.commit()
        
        with patch('backend.services.cluster_manager_service.routers.clusters.test_kubernetes_connection') as mock_test:
            mock_test.return_value = {
                "connected": True,
                "server_version": "v1.26.0",
                "cluster_info": {"nodes": 3, "ready_nodes": 3}
            }
            
            response = test_client.get(f"/api/clusters/{cluster.id}/test-connection", headers=auth_headers)
            
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert data["data"]["connected"] is True
            assert "server_version" in data["data"]
    
    def test_apply_yaml_manifest(self, test_client, auth_headers, test_db_session, admin_user):
        """Test applying YAML manifest to cluster."""
        cluster = ClusterFactory(name="yaml-test-cluster", created_by=admin_user.id)
        test_db_session.add(cluster)
        test_db_session.commit()
        
        yaml_manifest = """
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-config
  namespace: default
data:
  key1: value1
"""
        
        manifest_data = {"yaml": yaml_manifest}
        
        with patch('backend.services.cluster_manager_service.routers.clusters.apply_yaml_manifest') as mock_apply:
            mock_apply.return_value = {
                "applied": True,
                "resources": [{"kind": "ConfigMap", "name": "test-config", "namespace": "default"}]
            }
            
            response = test_client.post(
                f"/api/clusters/{cluster.id}/apply",
                json=manifest_data,
                headers=auth_headers
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert data["data"]["applied"] is True


@pytest.mark.integration
class TestClusterAuditLogging:
    """Integration tests for cluster operation audit logging."""
    
    def test_cluster_operations_are_audited(self, test_client, auth_headers, test_db_session, admin_user):
        """Test that cluster operations are properly audited."""
        cluster_data = {
            "name": "audit-test-cluster",
            "description": "Cluster for audit testing",
            "provider": "aws",
            "region": "us-west-2",
            "kubeconfig": base64.b64encode(b"test-config").decode()
        }
        
        with patch('backend.services.cluster_manager_service.routers.clusters.validate_kubeconfig') as mock_validate:
            with patch('backend.services.cluster_manager_service.routers.clusters.log_audit_event') as mock_audit:
                mock_validate.return_value = True
                
                response = test_client.post("/api/clusters", json=cluster_data, headers=auth_headers)
                
                assert response.status_code == 201
                
                # Verify audit log was created
                mock_audit.assert_called_once()
                audit_call = mock_audit.call_args
                assert audit_call[1]["action"] == "create_cluster"
                assert audit_call[1]["resource_type"] == "cluster" 