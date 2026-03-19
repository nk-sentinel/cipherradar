import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { MOCK_PORTFOLIO_COMPLIANCE } from '../../src/mocks/data/compliance.ts';
import { Compliance } from '../../src/pages/Compliance.tsx';
import {
  createRouter,
  createRootRoute,
  createRoute,
  RouterProvider,
  createMemoryHistory,
} from '@tanstack/react-router';

const server = setupServer(
  http.get('/api/v1/compliance/portfolio', () => {
    return HttpResponse.json(MOCK_PORTFOLIO_COMPLIANCE);
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
  const complianceRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/compliance',
    component: Compliance,
  });

  const routeTree = rootRoute.addChildren([complianceRoute]);

  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ['/compliance'] }),
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('Compliance page', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* jsdom may not support */ }
  });

  it('renders the page title', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Compliance (Portfolio)')).toBeInTheDocument();
    });
  });

  it('renders NIST framework card with score', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getAllByText('NIST 800-131A').length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText('72%')).toBeInTheDocument();
    });
  });

  it('renders FIPS framework card with score', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getAllByText('FIPS 140-3').length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText('65%').length).toBeGreaterThanOrEqual(1);
    });
  });

  it('renders CNSA framework card with score', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getAllByText('CNSA 2.0').length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText('38%').length).toBeGreaterThanOrEqual(1);
    });
  });

  it('renders compliance by repository table', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('data-pipeline')).toBeInTheDocument();
      expect(screen.getByText('auth-api')).toBeInTheDocument();
      expect(screen.getByText('payment-service')).toBeInTheDocument();
      expect(screen.getByText('mobile-backend')).toBeInTheDocument();
    });
  });

  it('renders disallowed counts', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Compliance by Repository')).toBeInTheDocument();
      // data-pipeline has 0 disallowed, mobile-backend has 14
      expect(screen.getByText('0')).toBeInTheDocument();
      expect(screen.getByText('14')).toBeInTheDocument();
    });
  });
});
