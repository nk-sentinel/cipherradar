import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { MOCK_CERTIFICATES } from '../../src/mocks/data/certificates.ts';
import { CertCalendar } from '../../src/pages/CertCalendar.tsx';
import {
  createRouter,
  createRootRoute,
  createRoute,
  RouterProvider,
  createMemoryHistory,
} from '@tanstack/react-router';

const server = setupServer(
  http.get('/api/v1/certificates', () => {
    return HttpResponse.json(MOCK_CERTIFICATES);
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
    path: '/certificates',
    component: CertCalendar,
  });

  const routeTree = rootRoute.addChildren([certRoute]);

  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ['/certificates'] }),
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('CertCalendar page', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* jsdom may not support */ }
  });

  it('renders the page title', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Certificate Expiry Calendar')).toBeInTheDocument();
    });
  });

  it('renders stat cards', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Total Certs')).toBeInTheDocument();
      expect(screen.getByText('Expired')).toBeInTheDocument();
    });
  });

  it('renders calendar and list toggle buttons', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Calendar')).toBeInTheDocument();
      expect(screen.getByText('List')).toBeInTheDocument();
    });
  });

  it('renders day-of-week headers in calendar mode', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Mon')).toBeInTheDocument();
      expect(screen.getByText('Tue')).toBeInTheDocument();
      expect(screen.getByText('Wed')).toBeInTheDocument();
    });
  });

  it('switches to list view and shows table', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('List')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('List'));

    await waitFor(() => {
      expect(screen.getByText('Common Name')).toBeInTheDocument();
      expect(screen.getByText('Issuer')).toBeInTheDocument();
      expect(screen.getByText('Expiry Date')).toBeInTheDocument();
    });
  });

  it('renders certificate total count', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText(String(MOCK_CERTIFICATES.length))).toBeInTheDocument();
    });
  });

  it('renders select a day placeholder', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Select a day')).toBeInTheDocument();
    });
  });
});
