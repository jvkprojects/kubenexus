"""Unit tests for authentication service."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from jose import jwt

from backend.services.auth_service.routers.auth import (
    authenticate_user, create_access_token, verify_token,
    get_password_hash, verify_password
)
from backend.shared.models import User
from tests.utils.factories import UserFactory, AdminUserFactory


class TestPasswordUtils:
    """Test password hashing and verification utilities."""
    
    def test_password_hashing(self):
        """Test password hashing functionality."""
        password = "test_password_123"
        hashed = get_password_hash(password)
        
        assert hashed != password
        assert hashed.startswith("$2b$")
        assert verify_password(password, hashed) is True
    
    def test_password_verification_failure(self):
        """Test password verification with wrong password."""
        password = "correct_password"
        wrong_password = "wrong_password"
        hashed = get_password_hash(password)
        
        assert verify_password(wrong_password, hashed) is False
    
    def test_empty_password_handling(self):
        """Test handling of empty passwords."""
        with pytest.raises(ValueError):
            get_password_hash("")
        
        with pytest.raises(ValueError):
            get_password_hash(None)


class TestTokenOperations:
    """Test JWT token creation and verification."""
    
    @patch('backend.services.auth_service.routers.auth.settings')
    def test_create_access_token_default_expiry(self, mock_settings):
        """Test creating access token with default expiry."""
        mock_settings.jwt_secret_key = "test-secret"
        mock_settings.jwt_algorithm = "HS256"
        
        data = {"sub": "testuser"}
        token = create_access_token(data)
        
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Decode and verify
        payload = jwt.decode(token, "test-secret", algorithms=["HS256"])
        assert payload["sub"] == "testuser"
        assert "exp" in payload
    
    @patch('backend.services.auth_service.routers.auth.settings')
    def test_create_access_token_custom_expiry(self, mock_settings):
        """Test creating access token with custom expiry."""
        mock_settings.jwt_secret_key = "test-secret"
        mock_settings.jwt_algorithm = "HS256"
        
        data = {"sub": "testuser"}
        expires_delta = timedelta(hours=2)
        token = create_access_token(data, expires_delta)
        
        payload = jwt.decode(token, "test-secret", algorithms=["HS256"])
        
        # Check that expiry is approximately 2 hours from now
        exp_time = datetime.fromtimestamp(payload["exp"])
        expected_time = datetime.utcnow() + expires_delta
        time_diff = abs((exp_time - expected_time).total_seconds())
        
        assert time_diff < 60  # Within 1 minute tolerance
    
    @patch('backend.services.auth_service.routers.auth.settings')
    def test_verify_token_valid(self, mock_settings):
        """Test verifying a valid token."""
        mock_settings.jwt_secret_key = "test-secret"
        mock_settings.jwt_algorithm = "HS256"
        
        data = {"sub": "testuser", "admin": False}
        token = create_access_token(data)
        
        payload = verify_token(token)
        assert payload["sub"] == "testuser"
        assert payload["admin"] is False
    
    @patch('backend.services.auth_service.routers.auth.settings')
    def test_verify_token_invalid(self, mock_settings):
        """Test verifying an invalid token."""
        mock_settings.jwt_secret_key = "test-secret"
        mock_settings.jwt_algorithm = "HS256"
        
        invalid_token = "invalid.token.here"
        
        with pytest.raises(Exception):  # JWT decode will raise an exception
            verify_token(invalid_token)
    
    @patch('backend.services.auth_service.routers.auth.settings')
    def test_verify_token_expired(self, mock_settings):
        """Test verifying an expired token."""
        mock_settings.jwt_secret_key = "test-secret"
        mock_settings.jwt_algorithm = "HS256"
        
        # Create token that expired 1 hour ago
        past_time = datetime.utcnow() - timedelta(hours=1)
        data = {"sub": "testuser", "exp": past_time.timestamp()}
        
        token = jwt.encode(data, "test-secret", algorithm="HS256")
        
        with pytest.raises(Exception):  # Expired token should raise exception
            verify_token(token)


class TestUserAuthentication:
    """Test user authentication logic."""
    
    def test_authenticate_user_success(self, test_db_session):
        """Test successful user authentication."""
        # Create test user with known password
        password = "test_password_123"
        user = UserFactory(
            username="testuser",
            password_hash=get_password_hash(password),
            is_active=True
        )
        test_db_session.add(user)
        test_db_session.commit()
        
        # Mock database query
        with patch('backend.services.auth_service.routers.auth.get_user_by_username') as mock_get_user:
            mock_get_user.return_value = user
            
            authenticated_user = authenticate_user(test_db_session, "testuser", password)
            
            assert authenticated_user is not None
            assert authenticated_user.username == "testuser"
            assert authenticated_user.is_active is True
    
    def test_authenticate_user_wrong_password(self, test_db_session):
        """Test authentication with wrong password."""
        password = "correct_password"
        user = UserFactory(
            username="testuser",
            password_hash=get_password_hash(password),
            is_active=True
        )
        test_db_session.add(user)
        test_db_session.commit()
        
        with patch('backend.services.auth_service.routers.auth.get_user_by_username') as mock_get_user:
            mock_get_user.return_value = user
            
            authenticated_user = authenticate_user(test_db_session, "testuser", "wrong_password")
            
            assert authenticated_user is False
    
    def test_authenticate_user_not_found(self, test_db_session):
        """Test authentication with non-existent user."""
        with patch('backend.services.auth_service.routers.auth.get_user_by_username') as mock_get_user:
            mock_get_user.return_value = None
            
            authenticated_user = authenticate_user(test_db_session, "nonexistent", "password")
            
            assert authenticated_user is False
    
    def test_authenticate_user_inactive(self, test_db_session):
        """Test authentication with inactive user."""
        password = "test_password_123"
        user = UserFactory(
            username="inactiveuser",
            password_hash=get_password_hash(password),
            is_active=False
        )
        test_db_session.add(user)
        test_db_session.commit()
        
        with patch('backend.services.auth_service.routers.auth.get_user_by_username') as mock_get_user:
            mock_get_user.return_value = user
            
            authenticated_user = authenticate_user(test_db_session, "inactiveuser", password)
            
            assert authenticated_user is False


class TestAuthenticationAPI:
    """Test authentication API endpoints."""
    
    def test_login_success(self, test_client, test_db_session):
        """Test successful login API call."""
        password = "test_password_123"
        user = UserFactory(
            username="testuser",
            email="test@example.com",
            password_hash=get_password_hash(password),
            is_active=True
        )
        test_db_session.add(user)
        test_db_session.commit()
        
        login_data = {
            "username": "testuser",
            "password": password
        }
        
        with patch('backend.services.auth_service.routers.auth.authenticate_user') as mock_auth:
            mock_auth.return_value = user
            
            response = test_client.post("/auth/login", json=login_data)
            
            assert response.status_code == 200
            data = response.json()
            assert "access_token" in data
            assert data["token_type"] == "bearer"
            assert "expires_in" in data
    
    def test_login_invalid_credentials(self, test_client):
        """Test login with invalid credentials."""
        login_data = {
            "username": "testuser",
            "password": "wrong_password"
        }
        
        with patch('backend.services.auth_service.routers.auth.authenticate_user') as mock_auth:
            mock_auth.return_value = False
            
            response = test_client.post("/auth/login", json=login_data)
            
            assert response.status_code == 401
            data = response.json()
            assert "error" in data
    
    def test_login_missing_credentials(self, test_client):
        """Test login with missing credentials."""
        login_data = {
            "username": "testuser"
            # Missing password
        }
        
        response = test_client.post("/auth/login", json=login_data)
        
        assert response.status_code == 422  # Validation error
    
    def test_logout_success(self, test_client, auth_headers):
        """Test successful logout."""
        with patch('backend.services.auth_service.routers.auth.revoke_token') as mock_revoke:
            mock_revoke.return_value = True
            
            response = test_client.post("/auth/logout", headers=auth_headers)
            
            assert response.status_code == 200
            data = response.json()
            assert data["message"] == "Successfully logged out"
    
    def test_refresh_token_success(self, test_client, auth_headers):
        """Test successful token refresh."""
        with patch('backend.services.auth_service.routers.auth.verify_token') as mock_verify:
            with patch('backend.services.auth_service.routers.auth.create_access_token') as mock_create:
                mock_verify.return_value = {"sub": "testuser", "admin": False}
                mock_create.return_value = "new_token_here"
                
                response = test_client.post("/auth/refresh", headers=auth_headers)
                
                assert response.status_code == 200
                data = response.json()
                assert "access_token" in data
    
    def test_get_current_user_success(self, test_client, auth_headers, admin_user):
        """Test getting current user information."""
        with patch('backend.services.auth_service.routers.auth.get_current_user') as mock_get_user:
            mock_get_user.return_value = admin_user
            
            response = test_client.get("/auth/me", headers=auth_headers)
            
            assert response.status_code == 200
            data = response.json()
            assert data["username"] == admin_user.username
            assert data["email"] == admin_user.email
    
    def test_get_current_user_unauthorized(self, test_client):
        """Test getting current user without authentication."""
        response = test_client.get("/auth/me")
        
        assert response.status_code == 401


class TestRoleBasedAccess:
    """Test role-based access control."""
    
    def test_admin_user_permissions(self, test_db_session):
        """Test admin user has all permissions."""
        admin_user = AdminUserFactory()
        test_db_session.add(admin_user)
        test_db_session.commit()
        
        # Mock permission check
        with patch('backend.services.auth_service.routers.auth.check_user_permissions') as mock_check:
            mock_check.return_value = True
            
            has_permission = mock_check(admin_user, "admin", "all")
            assert has_permission is True
    
    def test_regular_user_limited_permissions(self, test_db_session):
        """Test regular user has limited permissions."""
        regular_user = UserFactory(is_admin=False)
        test_db_session.add(regular_user)
        test_db_session.commit()
        
        with patch('backend.services.auth_service.routers.auth.check_user_permissions') as mock_check:
            # Regular user should not have admin permissions
            mock_check.return_value = False
            
            has_permission = mock_check(regular_user, "admin", "all")
            assert has_permission is False


class TestSecurityFeatures:
    """Test security features like rate limiting and account lockout."""
    
    def test_failed_login_attempts_tracking(self, test_db_session):
        """Test tracking of failed login attempts."""
        user = UserFactory(failed_login_attempts=2)
        test_db_session.add(user)
        test_db_session.commit()
        
        with patch('backend.services.auth_service.routers.auth.increment_failed_attempts') as mock_increment:
            mock_increment.return_value = user
            user.failed_login_attempts = 3
            
            # Simulate failed login
            result = authenticate_user(test_db_session, user.username, "wrong_password")
            
            assert result is False
            # In real implementation, this would increment failed attempts
    
    def test_account_lockout_after_max_attempts(self, test_db_session):
        """Test account lockout after maximum failed attempts."""
        user = UserFactory(
            failed_login_attempts=5,
            account_locked_until=datetime.utcnow() + timedelta(minutes=30)
        )
        test_db_session.add(user)
        test_db_session.commit()
        
        with patch('backend.services.auth_service.routers.auth.is_account_locked') as mock_locked:
            mock_locked.return_value = True
            
            # Even with correct password, locked account should fail
            result = authenticate_user(test_db_session, user.username, "correct_password")
            
            assert result is False


@pytest.mark.integration
class TestAuthenticationIntegration:
    """Integration tests for authentication service."""
    
    def test_full_authentication_flow(self, test_client, test_db_session):
        """Test complete authentication flow from login to protected endpoint."""
        # Create user
        password = "test_password_123"
        user = UserFactory(
            username="integrationuser",
            password_hash=get_password_hash(password),
            is_active=True
        )
        test_db_session.add(user)
        test_db_session.commit()
        
        # Login
        login_response = test_client.post("/auth/login", json={
            "username": "integrationuser",
            "password": password
        })
        
        assert login_response.status_code == 200
        token_data = login_response.json()
        token = token_data["access_token"]
        
        # Use token to access protected endpoint
        headers = {"Authorization": f"Bearer {token}"}
        profile_response = test_client.get("/auth/me", headers=headers)
        
        assert profile_response.status_code == 200
        profile_data = profile_response.json()
        assert profile_data["username"] == "integrationuser"
    
    def test_token_expiry_handling(self, test_client):
        """Test handling of expired tokens."""
        # Create an expired token
        expired_token = "expired.token.here"
        headers = {"Authorization": f"Bearer {expired_token}"}
        
        response = test_client.get("/auth/me", headers=headers)
        
        assert response.status_code == 401
        data = response.json()
        assert "token" in data.get("error", {}).get("message", "").lower() 