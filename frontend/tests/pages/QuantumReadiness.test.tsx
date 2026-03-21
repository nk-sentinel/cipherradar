import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { MOCK_PORTFOLIO_QUANTUM } from '../../src/mocks/data/quantum.ts';
import { QuantumReadiness } from '../../src/pages/QuantumReadiness.tsx';
import {
  createRouter,
  createRootRoute,
  createRoute,
  RouterProvider,
  createMemoryHistory,
} from '@tanstack/react-router';

const server = setupServer(
  http.get('/api/v1/portfolio/quantum', () => {
    return HttpResponse.json(MOCK_PORTFOLIO_QUANTUM);
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
  const quantumRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/quantum',
    component: QuantumReadiness,
  });

  const routeTree = rootRoute.addChildren([quantumRoute]);

  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ['/quantum'] }),
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('QuantumReadiness page', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* jsdom may not support */ }
  });

  it('renders the page title', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Quantum Readiness (Portfolio)')).toBeInTheDocument();
    });
  });

  it('renders the org risk score', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('58')).toBeInTheDocument();
      expect(screen.getByText('Org Quantum Risk Score')).toBeInTheDocument();
    });
  });

  it('renders vulnerable algorithm count', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('312')).toBeInTheDocument();
      expect(screen.getByText('Vulnerable Algorithms')).toBeInTheDocument();
    });
  });

  it('renders migration effort', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('~6mo')).toBeInTheDocument();
      expect(screen.getByText('Est. Migration Effort')).toBeInTheDocument();
    });
  });

  it('renders migration priority table', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('RSA')).toBeInTheDocument();
      expect(screen.getByText('ECDSA')).toBeInTheDocument();
      expect(screen.getByText('ECDH')).toBeInTheDocument();
      expect(screen.getByText('ML-KEM / ML-DSA')).toBeInTheDocument();
    });
  });

  it('renders risk by repository table', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('payment-service')).toBeInTheDocument();
      expect(screen.getByText('mobile-backend')).toBeInTheDocument();
      expect(screen.getByText('auth-api')).toBeInTheDocument();
      expect(screen.getByText('data-pipeline')).toBeInTheDocument();
    });
  });

  it('renders quantum status breakdown', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Quantum Status Breakdown')).toBeInTheDocument();
      // "Vulnerable" appears in both the migration table header and the status breakdown
      expect(screen.getAllByText('Vulnerable').length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText('Safe').length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText('Unknown')).toBeInTheDocument();
      expect(screen.getByText('Broken')).toBeInTheDocument();
    });
  });
});
