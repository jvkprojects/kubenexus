/**
 * Tests for Dashboard component
 */

import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
import { rest } from 'msw';
import { setupServer } from 'msw/node';

import Dashboard from '../../pages/Dashboard';
import { AuthProvider } from '../../contexts/AuthContext';
import { BrowserRouter } from 'react-router-dom';

// Mock data
const mockClusters = [
  {
    id: 1,
    name: 'production-cluster',
    provider: 'aws',
    region: 'us-west-2',
    status: 'active',
    created_at: '2023-01-01T00:00:00Z',
    metadata: { nodeCount: 5 }
  },
  {
    id: 2,
    name: 'development-cluster',
    provider: 'gcp',
    region: 'us-central1',
    status: 'active',
    created_at: '2023-01-02T00:00:00Z',
    metadata: { nodeCount: 2 }
  }
];

const mockMetrics = {
  totalClusters: 2,
  activeClusters: 2,
  totalNodes: 7,
  totalPods: 45,
  cpuUsage: 65.4,
  memoryUsage: 78.2,
  alerts: 3
};

const mockAlerts = [
  {
    id: 1,
    title: 'High CPU usage detected',
    severity: 'warning',
    cluster: 'production-cluster',
    timestamp: '2023-01-01T12:00:00Z'
  },
  {
    id: 2,
    title: 'Pod restart loop',
    severity: 'error',
    cluster: 'production-cluster',
    timestamp: '2023-01-01T11:30:00Z'
  }
];

const mockUser = {
  username: 'testuser',
  email: 'test@example.com',
  is_admin: false
};

// MSW server setup
const server = setupServer(
  rest.get('/api/clusters', (req, res, ctx) => {
    return res(
      ctx.json({
        status: 'success',
        data: mockClusters,
        pagination: { page: 1, total: 2, pages: 1 }
      })
    );
  }),
  
  rest.get('/api/dashboard/metrics', (req, res, ctx) => {
    return res(
      ctx.json({
        status: 'success',
        data: mockMetrics
      })
    );
  }),
  
  rest.get('/api/alerts', (req, res, ctx) => {
    return res(
      ctx.json({
        status: 'success',
        data: mockAlerts
      })
    );
  })
);

// Test wrapper component
const TestWrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return (
    <BrowserRouter>
      <AuthProvider>
        {children}
      </AuthProvider>
    </BrowserRouter>
  );
};

// Helper function to render Dashboard with context
const renderDashboard = () => {
  return render(
    <TestWrapper>
      <Dashboard />
    </TestWrapper>
  );
};

describe('Dashboard Component', () => {
  beforeAll(() => server.listen());
  afterEach(() => server.resetHandlers());
  afterAll(() => server.close());

  describe('Initial Rendering', () => {
    test('renders dashboard title', async () => {
      renderDashboard();
      
      expect(screen.getByText('Dashboard')).toBeInTheDocument();
    });

    test('shows loading state initially', async () => {
      renderDashboard();
      
      expect(screen.getByTestId('loading-spinner')).toBeInTheDocument();
    });

    test('renders metrics cards after loading', async () => {
      renderDashboard();
      
      await waitFor(() => {
        expect(screen.getByText('Total Clusters')).toBeInTheDocument();
        expect(screen.getByText('2')).toBeInTheDocument();
      });
      
      expect(screen.getByText('Active Clusters')).toBeInTheDocument();
      expect(screen.getByText('Total Nodes')).toBeInTheDocument();
      expect(screen.getByText('7')).toBeInTheDocument();
    });
  });

  describe('Metrics Display', () => {
    test('displays correct cluster metrics', async () => {
      renderDashboard();
      
      await waitFor(() => {
        expect(screen.getByText('2')).toBeInTheDocument(); // Total clusters
        expect(screen.getByText('2')).toBeInTheDocument(); // Active clusters
        expect(screen.getByText('7')).toBeInTheDocument(); // Total nodes
        expect(screen.getByText('45')).toBeInTheDocument(); // Total pods
      });
    });

    test('displays resource usage percentages', async () => {
      renderDashboard();
      
      await waitFor(() => {
        expect(screen.getByText('65.4%')).toBeInTheDocument(); // CPU usage
        expect(screen.getByText('78.2%')).toBeInTheDocument(); // Memory usage
      });
    });

    test('shows alerts count', async () => {
      renderDashboard();
      
      await waitFor(() => {
        expect(screen.getByText('3')).toBeInTheDocument(); // Alerts count
      });
    });
  });

  describe('Clusters List', () => {
    test('displays cluster cards', async () => {
      renderDashboard();
      
      await waitFor(() => {
        expect(screen.getByText('production-cluster')).toBeInTheDocument();
        expect(screen.getByText('development-cluster')).toBeInTheDocument();
      });
    });

    test('shows cluster provider and region', async () => {
      renderDashboard();
      
      await waitFor(() => {
        expect(screen.getByText('aws')).toBeInTheDocument();
        expect(screen.getByText('us-west-2')).toBeInTheDocument();
        expect(screen.getByText('gcp')).toBeInTheDocument();
        expect(screen.getByText('us-central1')).toBeInTheDocument();
      });
    });

    test('displays cluster status badges', async () => {
      renderDashboard();
      
      await waitFor(() => {
        const statusBadges = screen.getAllByText('active');
        expect(statusBadges).toHaveLength(2);
      });
    });

    test('shows cluster node count', async () => {
      renderDashboard();
      
      await waitFor(() => {
        expect(screen.getByText('5 nodes')).toBeInTheDocument();
        expect(screen.getByText('2 nodes')).toBeInTheDocument();
      });
    });
  });

  describe('Alerts Section', () => {
    test('displays recent alerts', async () => {
      renderDashboard();
      
      await waitFor(() => {
        expect(screen.getByText('Recent Alerts')).toBeInTheDocument();
        expect(screen.getByText('High CPU usage detected')).toBeInTheDocument();
        expect(screen.getByText('Pod restart loop')).toBeInTheDocument();
      });
    });

    test('shows alert severity indicators', async () => {
      renderDashboard();
      
      await waitFor(() => {
        expect(screen.getByText('warning')).toBeInTheDocument();
        expect(screen.getByText('error')).toBeInTheDocument();
      });
    });

    test('displays alert timestamps', async () => {
      renderDashboard();
      
      await waitFor(() => {
        // Check for formatted time (implementation dependent)
        expect(screen.getByText(/12:00/)).toBeInTheDocument();
        expect(screen.getByText(/11:30/)).toBeInTheDocument();
      });
    });
  });

  describe('Interactive Elements', () => {
    test('cluster card click navigates to cluster details', async () => {
      renderDashboard();
      
      await waitFor(() => {
        const clusterCard = screen.getByTestId('cluster-card-1');
        fireEvent.click(clusterCard);
      });
      
      // Verify navigation (mock router or check window.location)
      expect(window.location.pathname).toBe('/clusters/1');
    });

    test('refresh button reloads dashboard data', async () => {
      renderDashboard();
      
      await waitFor(() => {
        const refreshButton = screen.getByTestId('refresh-button');
        fireEvent.click(refreshButton);
      });
      
      // Verify loading state appears again
      expect(screen.getByTestId('loading-spinner')).toBeInTheDocument();
    });

    test('view all clusters link navigates to clusters page', async () => {
      renderDashboard();
      
      await waitFor(() => {
        const viewAllLink = screen.getByText('View All Clusters');
        fireEvent.click(viewAllLink);
      });
      
      expect(window.location.pathname).toBe('/clusters');
    });
  });

  describe('Error Handling', () => {
    test('displays error message when API calls fail', async () => {
      // Override default handlers with error responses
      server.use(
        rest.get('/api/clusters', (req, res, ctx) => {
          return res(ctx.status(500), ctx.json({ error: 'Internal server error' }));
        }),
        rest.get('/api/dashboard/metrics', (req, res, ctx) => {
          return res(ctx.status(500), ctx.json({ error: 'Internal server error' }));
        })
      );

      renderDashboard();
      
      await waitFor(() => {
        expect(screen.getByText(/Error loading dashboard data/)).toBeInTheDocument();
      });
    });

    test('shows retry button on error', async () => {
      server.use(
        rest.get('/api/clusters', (req, res, ctx) => {
          return res(ctx.status(500), ctx.json({ error: 'Internal server error' }));
        })
      );

      renderDashboard();
      
      await waitFor(() => {
        expect(screen.getByText('Retry')).toBeInTheDocument();
      });
    });

    test('retry button reloads data after error', async () => {
      let callCount = 0;
      server.use(
        rest.get('/api/clusters', (req, res, ctx) => {
          callCount++;
          if (callCount === 1) {
            return res(ctx.status(500), ctx.json({ error: 'Internal server error' }));
          }
          return res(ctx.json({
            status: 'success',
            data: mockClusters,
            pagination: { page: 1, total: 2, pages: 1 }
          }));
        })
      );

      renderDashboard();
      
      await waitFor(() => {
        const retryButton = screen.getByText('Retry');
        fireEvent.click(retryButton);
      });
      
      await waitFor(() => {
        expect(screen.getByText('production-cluster')).toBeInTheDocument();
      });
    });
  });

  describe('Responsive Design', () => {
    test('adjusts layout on mobile screens', async () => {
      // Mock window.matchMedia for responsive design testing
      Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: jest.fn().mockImplementation(query => ({
          matches: query === '(max-width: 768px)',
          media: query,
          onchange: null,
          addListener: jest.fn(),
          removeListener: jest.fn(),
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          dispatchEvent: jest.fn(),
        })),
      });

      renderDashboard();
      
      await waitFor(() => {
        const metricsContainer = screen.getByTestId('metrics-container');
        expect(metricsContainer).toHaveClass('mobile-layout');
      });
    });
  });

  describe('Real-time Updates', () => {
    test('updates metrics when WebSocket message received', async () => {
      // Mock WebSocket
      const mockWebSocket = {
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
        send: jest.fn(),
        close: jest.fn(),
      };
      
      global.WebSocket = jest.fn(() => mockWebSocket) as any;

      renderDashboard();
      
      await waitFor(() => {
        expect(screen.getByText('2')).toBeInTheDocument(); // Initial clusters count
      });

      // Simulate WebSocket message
      const wsMessageHandler = mockWebSocket.addEventListener.mock.calls
        .find(call => call[0] === 'message')?.[1];
      
      if (wsMessageHandler) {
        wsMessageHandler({
          data: JSON.stringify({
            type: 'metrics_update',
            data: { ...mockMetrics, totalClusters: 3 }
          })
        });
      }

      await waitFor(() => {
        expect(screen.getByText('3')).toBeInTheDocument(); // Updated clusters count
      });
    });
  });

  describe('Accessibility', () => {
    test('has proper ARIA labels', async () => {
      renderDashboard();
      
      await waitFor(() => {
        expect(screen.getByRole('main')).toHaveAttribute('aria-label', 'Dashboard');
        expect(screen.getByRole('region', { name: 'Cluster Metrics' })).toBeInTheDocument();
        expect(screen.getByRole('region', { name: 'Recent Alerts' })).toBeInTheDocument();
      });
    });

    test('supports keyboard navigation', async () => {
      renderDashboard();
      
      await waitFor(() => {
        const clusterCard = screen.getByTestId('cluster-card-1');
        clusterCard.focus();
        expect(clusterCard).toHaveFocus();
        
        fireEvent.keyDown(clusterCard, { key: 'Enter' });
        expect(window.location.pathname).toBe('/clusters/1');
      });
    });

    test('provides screen reader friendly content', async () => {
      renderDashboard();
      
      await waitFor(() => {
        expect(screen.getByText('2 total clusters')).toBeInTheDocument();
        expect(screen.getByText('CPU usage at 65.4 percent')).toBeInTheDocument();
        expect(screen.getByText('Memory usage at 78.2 percent')).toBeInTheDocument();
      });
    });
  });

  describe('Performance', () => {
    test('memoizes expensive calculations', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      renderDashboard();
      
      // Trigger re-render with same props
      await waitFor(() => {
        fireEvent.click(screen.getByTestId('refresh-button'));
      });
      
      // Verify memoization worked (implementation dependent)
      expect(consoleSpy).not.toHaveBeenCalledWith('Expensive calculation performed');
      
      consoleSpy.mockRestore();
    });

    test('lazy loads non-critical components', async () => {
      renderDashboard();
      
      // Initially, advanced charts should not be loaded
      expect(screen.queryByTestId('advanced-charts')).not.toBeInTheDocument();
      
      // Scroll to trigger lazy loading
      fireEvent.scroll(window, { target: { scrollY: 800 } });
      
      await waitFor(() => {
        expect(screen.getByTestId('advanced-charts')).toBeInTheDocument();
      });
    });
  });
}); 