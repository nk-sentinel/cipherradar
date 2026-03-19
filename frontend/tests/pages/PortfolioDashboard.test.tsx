import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { MOCK_PORTFOLIO_SUMMARY } from '../../src/mocks/data/portfolio.ts';
import { MOCK_HEAT_MAP } from '../../src/mocks/data/portfolio.ts';
import { PortfolioDashboard } from '../../src/pages/PortfolioDashboard.tsx';
import { AuthProvider } from '../../src/lib/auth.tsx';
import {
  createRouter,
  createRootRoute,
  createRoute,
  RouterProvider,
  createMemoryHistory,
} from '@tanstack/react-router';

const server = setupServer(
  http.get('/api/v1/portfolio/summary', () => {
    return HttpResponse.json(MOCK_PORTFOLIO_SUMMARY);
  }),
  http.get('/api/v1/portfolio/heatmap', () => {
    return HttpResponse.json(MOCK_HEAT_MAP);
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderWithProviders() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });

  const rootRoute = createRootRoute();
  const dashboardRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/',
    component: PortfolioDashboard,
  });

  const routeTree = rootRoute.addChildren([dashboardRoute]);

  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ['/'] }),
  });

  return render(
    <AuthProvider>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </AuthProvider>,
  );
}

describe('PortfolioDashboard page', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* jsdom may not support */ }
  });

  it('renders the page title', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Dashboard')).toBeInTheDocument();
    });
  });

  it('renders stat cards with correct values', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('1,247')).toBeInTheDocument();
      expect(screen.getByText('89')).toBeInTheDocument();
      expect(screen.getByText('312')).toBeInTheDocument();
      expect(screen.getByText('72%')).toBeInTheDocument();
    });
  });

  it('renders the quantum readiness gauge', async () => {
    renderWithProviders();
    await waitFor(() => {
      const gauge = screen.getByTestId('quantum-gauge');
      expect(gauge).toBeInTheDocument();
      expect(gauge.textContent).toBe('58%');
    });
  });

  it('renders the heat map with repository names', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Severity Heat Map')).toBeInTheDocument();
      expect(screen.getByText('payment-service')).toBeInTheDocument();
      expect(screen.getByText('mobile-backend')).toBeInTheDocument();
      expect(screen.getByText('data-pipeline')).toBeInTheDocument();
    });
  });

  it('renders the top riskiest repositories table', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Top Riskiest Repositories')).toBeInTheDocument();
      // Check top repos are present
      expect(screen.getByText('api-gateway')).toBeInTheDocument();
      expect(screen.getByText('user-service')).toBeInTheDocument();
    });
  });

  it('renders severity distribution chart section', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Severity Distribution (All Repos)')).toBeInTheDocument();
    });
  });
});
