import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { CertificateTracker } from '../../src/pages/CertificateTracker.tsx';
import {
  createRouter,
  createRootRoute,
  createRoute,
  RouterProvider,
  createMemoryHistory,
} from '@tanstack/react-router';

const MOCK_CERTS = {
  items: [
    {
      id: 'cert-001',
      subject: 'api.payment.internal',
      issuer: 'Internal CA',
      notAfter: '2026-01-15T00:00:00Z',
      statusColor: 'black',
      daysRemaining: -71,
      projectName: 'payment-service',
      projectId: 'proj-001',
      filePath: 'certs/api.pem',
    },
    {
      id: 'cert-002',
      subject: 'auth.internal',
      issuer: 'Internal CA',
      notAfter: '2026-04-10T00:00:00Z',
      statusColor: 'red',
      daysRemaining: 14,
      projectName: 'auth-api',
      projectId: 'proj-002',
      filePath: 'certs/auth.pem',
    },
    {
      id: 'cert-003',
      subject: 'webhook.example.com',
      issuer: "Let's Encrypt R3",
      notAfter: '2026-06-15T00:00:00Z',
      statusColor: 'amber',
      daysRemaining: 80,
      projectName: 'auth-api',
      projectId: 'proj-002',
      filePath: 'certs/webhook.pem',
    },
    {
      id: 'cert-004',
      subject: 'Root CA',
      issuer: 'Self-signed',
      notAfter: '2026-09-23T00:00:00Z',
      statusColor: 'green',
      daysRemaining: 180,
      projectName: 'payment-service',
      projectId: 'proj-001',
      filePath: 'certs/root-ca.pem',
    },
  ],
  total: 4,
  page: 1,
  perPage: 25,
};

const server = setupServer(
  http.get('/api/v1/portfolio/certificates', ({ request }) => {
    const url = new URL(request.url);
    const statusColor = url.searchParams.get('status_color');
    let items = MOCK_CERTS.items;
    if (statusColor) {
      items = items.filter((c) => c.statusColor === statusColor);
    }
    return HttpResponse.json({
      ...MOCK_CERTS,
      items,
      total: items.length,
    });
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
  const certRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/certificate-tracker',
    component: CertificateTracker,
  });

  const routeTree = rootRoute.addChildren([certRoute]);

  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ['/certificate-tracker'] }),
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('CertificateTracker page', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* jsdom may not support */ }
  });

  it('renders the table with certificate data', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Certificate Tracker')).toBeInTheDocument();
      expect(screen.getByText('api.payment.internal')).toBeInTheDocument();
      expect(screen.getByText('auth.internal')).toBeInTheDocument();
      expect(screen.getByText('webhook.example.com')).toBeInTheDocument();
      expect(screen.getByText('Root CA')).toBeInTheDocument();
    });
  });

  it('renders color status badges', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Expired')).toBeInTheDocument();
    });
    // Should see different badge classes for different statuses
    const badges = screen.getAllByTestId('cert-status-badge');
    expect(badges.length).toBeGreaterThanOrEqual(1);
  });

  it('renders filter dropdown with status options', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Certificate Tracker')).toBeInTheDocument();
    });
    const filterSelect = screen.getByTestId('cert-status-filter');
    expect(filterSelect).toBeInTheDocument();

    // Change filter to 'red'
    fireEvent.change(filterSelect, { target: { value: 'red' } });
    await waitFor(() => {
      expect(screen.getByText('auth.internal')).toBeInTheDocument();
    });
  });
});
