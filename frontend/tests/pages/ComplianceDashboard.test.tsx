import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { MOCK_COMPLIANCE_DASHBOARD } from '../../src/mocks/data/complianceDashboard.ts';
import { ComplianceDashboard } from '../../src/pages/ComplianceDashboard.tsx';
import {
  createRouter,
  createRootRoute,
  createRoute,
  RouterProvider,
  createMemoryHistory,
} from '@tanstack/react-router';

const server = setupServer(
  http.get('/api/v1/compliance/dashboard', () => {
    return HttpResponse.json(MOCK_COMPLIANCE_DASHBOARD);
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

  // Mock ResizeObserver for Recharts
  if (typeof window !== 'undefined' && !window.ResizeObserver) {
    window.ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    } as unknown as typeof ResizeObserver;
  }

  const rootRoute = createRootRoute();
  const compDashRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/compliance-dashboard',
    component: ComplianceDashboard,
  });

  const routeTree = rootRoute.addChildren([compDashRoute]);

  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ['/compliance-dashboard'] }),
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('ComplianceDashboard page', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* jsdom may not support */ }
  });

  it('renders the page title', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Compliance Dashboard')).toBeInTheDocument();
    });
  });

  it('renders all 6 framework cards', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('NIST 800-131A')).toBeInTheDocument();
      expect(screen.getByText('FIPS 140-3')).toBeInTheDocument();
      expect(screen.getByText('PCI-DSS v4.0')).toBeInTheDocument();
      expect(screen.getByText('CNSA 2.0')).toBeInTheDocument();
      expect(screen.getByText('ISO 27001 A.8.24')).toBeInTheDocument();
      expect(screen.getByText('EU CRA')).toBeInTheDocument();
    });
  });

  it('renders NIST score', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('72%')).toBeInTheDocument();
    });
  });

  it('renders CNSA 2.0 timeline section', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('CNSA 2.0 Migration Timeline')).toBeInTheDocument();
    });
  });

  it('renders cross-repo comparison section', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Cross-Repository Comparison')).toBeInTheDocument();
    });
  });

  it('renders compliance by repository table', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Compliance by Repository')).toBeInTheDocument();
      expect(screen.getByText('payment-service')).toBeInTheDocument();
      expect(screen.getByText('auth-api')).toBeInTheDocument();
      expect(screen.getByText('data-pipeline')).toBeInTheDocument();
      expect(screen.getByText('mobile-backend')).toBeInTheDocument();
    });
  });

  it('renders gap report download button', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Download Gap Report (PDF)')).toBeInTheDocument();
    });
  });
});
