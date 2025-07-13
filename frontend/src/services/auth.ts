import { authAPI } from './api';
import { User, LoginCredentials, AuthResponse } from '../types';

class AuthService {
  private static instance: AuthService;
  
  private constructor() {}
  
  static getInstance(): AuthService {
    if (!AuthService.instance) {
      AuthService.instance = new AuthService();
    }
    return AuthService.instance;
  }

  async login(credentials: LoginCredentials): Promise<AuthResponse> {
    try {
      const response = await authAPI.login(credentials);
      
      if (response.success && response.data) {
        // Store tokens and user info
        localStorage.setItem('token', response.data.access_token);
        localStorage.setItem('refresh_token', response.data.refresh_token);
        localStorage.setItem('user', JSON.stringify(response.data.user));
        
        return response.data;
      } else {
        throw new Error(response.message || 'Login failed');
      }
    } catch (error: any) {
      throw new Error(error.response?.data?.message || error.message || 'Login failed');
    }
  }

  async logout(): Promise<void> {
    try {
      await authAPI.logout();
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Clear local storage regardless of API response
      localStorage.removeItem('token');
      localStorage.removeItem('refresh_token');
      localStorage.removeItem('user');
    }
  }

  async getCurrentUser(): Promise<User | null> {
    try {
      const response = await authAPI.getCurrentUser();
      
      if (response.success && response.data) {
        const user = response.data;
        localStorage.setItem('user', JSON.stringify(user));
        return user;
      }
      return null;
    } catch (error) {
      console.error('Get current user error:', error);
      return null;
    }
  }

  getToken(): string | null {
    return localStorage.getItem('token');
  }

  getUser(): User | null {
    const userStr = localStorage.getItem('user');
    if (userStr) {
      try {
        return JSON.parse(userStr);
      } catch (error) {
        console.error('Error parsing user from localStorage:', error);
        return null;
      }
    }
    return null;
  }

  isAuthenticated(): boolean {
    return !!this.getToken();
  }

  async refreshToken(): Promise<boolean> {
    try {
      const refreshToken = localStorage.getItem('refresh_token');
      if (!refreshToken) {
        return false;
      }

      const response = await authAPI.refreshToken(refreshToken);
      
      if (response.success && response.data) {
        localStorage.setItem('token', response.data.access_token);
        localStorage.setItem('refresh_token', response.data.refresh_token);
        return true;
      }
      return false;
    } catch (error) {
      console.error('Token refresh error:', error);
      return false;
    }
  }

  hasRole(role: string): boolean {
    const user = this.getUser();
    if (!user) return false;
    
    // Check both single role and roles array
    return user.role === role || user.roles.includes(role);
  }

  hasPermission(permission: string): boolean {
    const user = this.getUser();
    if (!user) return false;
    
    return user.permissions.includes(permission);
  }

  hasAnyRole(roles: string[]): boolean {
    const user = this.getUser();
    if (!user) return false;
    
    return roles.some(role => user.role === role || user.roles.includes(role));
  }

  hasAnyPermission(permissions: string[]): boolean {
    const user = this.getUser();
    if (!user) return false;
    
    return permissions.some(permission => user.permissions.includes(permission));
  }
}

export const authService = AuthService.getInstance(); 