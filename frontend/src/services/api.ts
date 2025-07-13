import axios from 'axios';
import { ApiResponse, User, LoginCredentials, AuthResponse, Cluster, AuditLog } from '../types';

// API Gateway base URL - using relative path for nginx proxy
const API_BASE_URL = '/api';

// Create axios instance with default config
const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor to handle errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Generic API response wrapper
const apiCall = async <T>(request: () => Promise<any>): Promise<ApiResponse<T>> => {
  try {
    const response = await request();
    return {
      success: true,
      data: response.data,
      message: response.data?.message || 'Success',
    };
  } catch (error: any) {
    return {
      success: false,
      message: error.response?.data?.message || error.message || 'An error occurred',
      errors: error.response?.data?.errors || [],
    };
  }
};

// Auth Service API calls
export const authAPI = {
  login: async (credentials: LoginCredentials): Promise<ApiResponse<AuthResponse>> => {
    return apiCall(() => api.post('/auth/login', credentials));
  },

  logout: async (): Promise<ApiResponse<void>> => {
    return apiCall(() => api.post('/auth/logout'));
  },

  getCurrentUser: async (): Promise<ApiResponse<User>> => {
    return apiCall(() => api.get('/auth/me'));
  },

  refreshToken: async (refreshToken: string): Promise<ApiResponse<AuthResponse>> => {
    return apiCall(() => api.post('/auth/refresh', { refresh_token: refreshToken }));
  },

  register: async (userData: Partial<User>): Promise<ApiResponse<User>> => {
    return apiCall(() => api.post('/auth/register', userData));
  },

  updateProfile: async (userData: Partial<User>): Promise<ApiResponse<User>> => {
    return apiCall(() => api.put('/auth/profile', userData));
  },

  changePassword: async (passwords: { currentPassword: string; newPassword: string }): Promise<ApiResponse<void>> => {
    return apiCall(() => api.put('/auth/change-password', passwords));
  },
};

// Cluster Manager Service API calls
export const clusterAPI = {
  getClusters: async (): Promise<ApiResponse<Cluster[]>> => {
    return apiCall(() => api.get('/clusters'));
  },

  getCluster: async (clusterId: string): Promise<ApiResponse<Cluster>> => {
    return apiCall(() => api.get(`/clusters/${clusterId}`));
  },

  createCluster: async (clusterData: Partial<Cluster>): Promise<ApiResponse<Cluster>> => {
    return apiCall(() => api.post('/clusters', clusterData));
  },

  updateCluster: async (clusterId: string, clusterData: Partial<Cluster>): Promise<ApiResponse<Cluster>> => {
    return apiCall(() => api.put(`/clusters/${clusterId}`, clusterData));
  },

  deleteCluster: async (clusterId: string): Promise<ApiResponse<void>> => {
    return apiCall(() => api.delete(`/clusters/${clusterId}`));
  },

  getClusterNodes: async (clusterId: string): Promise<ApiResponse<any[]>> => {
    return apiCall(() => api.get(`/clusters/${clusterId}/nodes`));
  },

  getClusterPods: async (clusterId: string, namespace?: string): Promise<ApiResponse<any[]>> => {
    const params = namespace ? { namespace } : {};
    return apiCall(() => api.get(`/clusters/${clusterId}/pods`, { params }));
  },

  getClusterServices: async (clusterId: string, namespace?: string): Promise<ApiResponse<any[]>> => {
    const params = namespace ? { namespace } : {};
    return apiCall(() => api.get(`/clusters/${clusterId}/services`, { params }));
  },

  getClusterDeployments: async (clusterId: string, namespace?: string): Promise<ApiResponse<any[]>> => {
    const params = namespace ? { namespace } : {};
    return apiCall(() => api.get(`/clusters/${clusterId}/deployments`, { params }));
  },

  getClusterMetrics: async (clusterId: string): Promise<ApiResponse<any[]>> => {
    return apiCall(() => api.get(`/clusters/${clusterId}/metrics`));
  },

  getKubeconfig: async (clusterId: string): Promise<ApiResponse<{ kubeconfig: string }>> => {
    return apiCall(() => api.get(`/clusters/${clusterId}/kubeconfig`));
  },
};

// Metrics Service API calls
export const metricsAPI = {
  getSystemMetrics: async (): Promise<ApiResponse<any>> => {
    return apiCall(() => api.get('/metrics/system'));
  },

  getClusterMetrics: async (clusterId: string): Promise<ApiResponse<any>> => {
    return apiCall(() => api.get(`/metrics/cluster/${clusterId}`));
  },

  getTimeSeriesMetrics: async (clusterId: string, metric: string, timeRange: string): Promise<ApiResponse<any>> => {
    return apiCall(() => api.get(`/metrics/timeseries/${clusterId}/${metric}`, { 
      params: { timeRange } 
    }));
  },

  getResourceUsage: async (clusterId: string, resourceType: string): Promise<ApiResponse<any>> => {
    return apiCall(() => api.get(`/metrics/usage/${clusterId}/${resourceType}`));
  },
};

// SRE Agent Service API calls
export const sreAPI = {
  getMonitoringStatus: async (): Promise<ApiResponse<any>> => {
    return apiCall(() => api.get('/sre/monitoring/status'));
  },

  getAlerts: async (clusterId?: string): Promise<ApiResponse<any[]>> => {
    const params = clusterId ? { clusterId } : {};
    return apiCall(() => api.get('/sre/alerts', { params }));
  },

  getAnomalies: async (clusterId?: string): Promise<ApiResponse<any[]>> => {
    const params = clusterId ? { clusterId } : {};
    return apiCall(() => api.get('/sre/anomalies', { params }));
  },

  getMLRecommendations: async (clusterId?: string): Promise<ApiResponse<any[]>> => {
    const params = clusterId ? { clusterId } : {};
    return apiCall(() => api.get('/sre/recommendations', { params }));
  },

  getInsights: async (clusterId?: string): Promise<ApiResponse<any[]>> => {
    const params = clusterId ? { clusterId } : {};
    return apiCall(() => api.get('/sre/insights', { params }));
  },
};

// Audit Log Service API calls
export const auditAPI = {
  getAuditLogs: async (params?: { 
    page?: number; 
    limit?: number; 
    userId?: string; 
    action?: string; 
    startDate?: string; 
    endDate?: string; 
  }): Promise<ApiResponse<AuditLog[]>> => {
    return apiCall(() => api.get('/audit/logs', { params }));
  },

  getAuditStats: async (): Promise<ApiResponse<any>> => {
    return apiCall(() => api.get('/audit/stats'));
  },

  searchAuditLogs: async (query: string): Promise<ApiResponse<AuditLog[]>> => {
    return apiCall(() => api.get('/audit/search', { params: { query } }));
  },

  exportAuditLogs: async (params?: { 
    format?: 'csv' | 'json'; 
    startDate?: string; 
    endDate?: string; 
  }): Promise<ApiResponse<{ downloadUrl: string }>> => {
    return apiCall(() => api.get('/audit/export', { params }));
  },
};

// Terminal Service API calls
export const terminalAPI = {
  createTerminalSession: async (clusterId: string, podName: string, containerName?: string): Promise<ApiResponse<{ sessionId: string }>> => {
    return apiCall(() => api.post('/terminal/session', { clusterId, podName, containerName }));
  },

  executeCommand: async (sessionId: string, command: string): Promise<ApiResponse<{ output: string }>> => {
    return apiCall(() => api.post(`/terminal/session/${sessionId}/execute`, { command }));
  },

  getTerminalLogs: async (sessionId: string): Promise<ApiResponse<{ logs: string[] }>> => {
    return apiCall(() => api.get(`/terminal/session/${sessionId}/logs`));
  },

  closeTerminalSession: async (sessionId: string): Promise<ApiResponse<void>> => {
    return apiCall(() => api.delete(`/terminal/session/${sessionId}`));
  },

  streamLogs: async (clusterId: string, podName: string, containerName?: string): Promise<ApiResponse<{ streamId: string }>> => {
    return apiCall(() => api.post('/terminal/logs/stream', { clusterId, podName, containerName }));
  },
};

// Health Check API calls
export const healthAPI = {
  getHealthStatus: async (): Promise<ApiResponse<any>> => {
    return apiCall(() => api.get('/health'));
  },

  getServiceHealth: async (serviceName: string): Promise<ApiResponse<any>> => {
    return apiCall(() => api.get(`/health/${serviceName}`));
  },

  getAllServicesHealth: async (): Promise<ApiResponse<any[]>> => {
    return apiCall(() => api.get('/health/all'));
  },
};

// User Management API calls (for admin users)
export const userAPI = {
  getUsers: async (params?: { page?: number; limit?: number; role?: string }): Promise<ApiResponse<User[]>> => {
    return apiCall(() => api.get('/users', { params }));
  },

  getUser: async (userId: string): Promise<ApiResponse<User>> => {
    return apiCall(() => api.get(`/users/${userId}`));
  },

  createUser: async (userData: Partial<User>): Promise<ApiResponse<User>> => {
    return apiCall(() => api.post('/users', userData));
  },

  updateUser: async (userId: string, userData: Partial<User>): Promise<ApiResponse<User>> => {
    return apiCall(() => api.put(`/users/${userId}`, userData));
  },

  deleteUser: async (userId: string): Promise<ApiResponse<void>> => {
    return apiCall(() => api.delete(`/users/${userId}`));
  },

  resetUserPassword: async (userId: string, newPassword: string): Promise<ApiResponse<void>> => {
    return apiCall(() => api.post(`/users/${userId}/reset-password`, { password: newPassword }));
  },
};

// Legacy API service for backward compatibility
export const apiService = {
  get: async <T>(url: string): Promise<ApiResponse<T>> => {
    return apiCall(() => api.get(url));
  },
  
  post: async <T>(url: string, data?: any): Promise<ApiResponse<T>> => {
    return apiCall(() => api.post(url, data));
  },
  
  put: async <T>(url: string, data?: any): Promise<ApiResponse<T>> => {
    return apiCall(() => api.put(url, data));
  },
  
  delete: async <T>(url: string): Promise<ApiResponse<T>> => {
    return apiCall(() => api.delete(url));
  },
};

export default api; 