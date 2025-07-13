export interface User {
  id: string;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string; // Single role for compatibility
  roles: string[]; // Array of roles for advanced permissions
  permissions: string[]; // User permissions
  isActive: boolean;
  createdAt: string;
  lastLogin?: string;
}

export interface Cluster {
  id: string;
  name: string;
  status: 'active' | 'inactive' | 'error' | 'pending';
  provider: 'aws' | 'gcp' | 'azure' | 'on-premises';
  region: string;
  version: string;
  nodes: number;
  nodeCount: number; // Total number of nodes in the cluster
  cost?: number; // Monthly cost estimate
  description?: string; // Cluster description
  environment?: string; // Environment type (dev, staging, prod)
  kubernetesVersion?: string; // Kubernetes version
  masterNodes?: number; // Number of master nodes
  workerNodes?: number; // Number of worker nodes
  totalPods?: number; // Total number of pods
  runningPods?: number; // Number of running pods
  cpuUsage?: number; // CPU usage percentage
  memoryUsage?: number; // Memory usage percentage
  storageUsage?: number; // Storage usage in GB
  networkUsage?: number; // Network usage
  lastHealthCheck?: string; // Last health check timestamp
  healthStatus?: 'healthy' | 'warning' | 'critical'; // Health status
  resourceUsage?: {
    cpu: number; // CPU usage percentage
    memory: number; // Memory usage percentage
    storage: number; // Storage usage percentage
    network?: number; // Network usage
  };
  createdAt: string;
  updatedAt: string;
}

export interface ClusterMetrics {
  clusterId: string;
  timestamp: string;
  cpuUsage: number;
  memoryUsage: number;
  diskUsage: number;
  networkIn: number;
  networkOut: number;
  podCount: number;
  nodeCount: number;
}

export interface Pod {
  id: string;
  name: string;
  namespace: string;
  clusterId: string;
  status: 'running' | 'pending' | 'failed' | 'succeeded';
  phase: string;
  containers: Container[];
  createdAt: string;
  updatedAt: string;
}

export interface Container {
  name: string;
  image: string;
  status: 'running' | 'waiting' | 'terminated';
  restartCount: number;
  ports: ContainerPort[];
}

export interface ContainerPort {
  containerPort: number;
  protocol: string;
  hostPort?: number;
}

export interface AuditLog {
  id: string;
  userId: string;
  username: string;
  action: string;
  resource: string;
  resourceId?: string;
  timestamp: string;
  ipAddress: string;
  userAgent: string;
  success: boolean;
  details?: any;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  message?: string;
  errors?: string[];
}

export interface DashboardStats {
  totalClusters: number;
  runningClusters: number;
  totalNodes: number;
  totalPods: number;
  totalUsers: number;
  activeUsers: number;
  monthlySpend: number;
  alerts: number;
}

export interface Alert {
  id: string;
  severity: 'critical' | 'warning' | 'info';
  title: string;
  message: string;
  clusterId?: string;
  namespace?: string;
  timestamp: string;
  resolved: boolean;
}

export interface ServiceHealth {
  name: string;
  status: 'healthy' | 'unhealthy' | 'unknown';
  responseTime?: number;
  uptime?: string;
  lastCheck: string;
}

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface AuthResponse {
  user: User;
  access_token: string;
  refresh_token: string;
  expires_at: string;
} 