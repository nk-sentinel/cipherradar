import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { MOCK_KANBAN_CARDS } from '../../src/mocks/data/kanban.ts';
import { MigrationKanban } from '../../src/pages/MigrationKanban.tsx';
import {
  createRouter,
  createRootRoute,
  createRoute,
  RouterProvider,
  createMemoryHistory,
} from '@tanstack/react-router';

const server = setupServer(
  http.get('/api/v1/kanban', () => {
    return HttpResponse.json(MOCK_KANBAN_CARDS);
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
  const kanbanRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/migration',
    component: MigrationKanban,
  });

  const routeTree = rootRoute.addChildren([kanbanRoute]);

  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ['/migration'] }),
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('MigrationKanban page', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* jsdom may not support */ }
  });

  it('renders the page title', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Migration Kanban')).toBeInTheDocument();
    });
  });

  it('renders all 4 kanban columns', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('To Do')).toBeInTheDocument();
      expect(screen.getByText('In Progress')).toBeInTheDocument();
      expect(screen.getByText('In Review')).toBeInTheDocument();
      expect(screen.getByText('Done')).toBeInTheDocument();
    });
  });

  it('renders kanban cards with finding names', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('RSA-2048 key generation')).toBeInTheDocument();
      expect(screen.getByText('ECDSA P-256 signatures')).toBeInTheDocument();
      expect(screen.getByText('ECDH key exchange')).toBeInTheDocument();
      expect(screen.getByText('RSA-4096 signing')).toBeInTheDocument();
    });
  });

  it('renders priority badges on cards', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('RSA-2048 key generation')).toBeInTheDocument();
      const criticals = screen.getAllByText('Critical');
      expect(criticals.length).toBeGreaterThanOrEqual(1);
      const highs = screen.getAllByText('High');
      expect(highs.length).toBeGreaterThanOrEqual(1);
    });
  });

  it('renders repo names on cards', async () => {
    renderWithProviders();
    await waitFor(() => {
      // Multiple cards reference these repos
      expect(screen.getAllByText('payment-service').length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText('auth-api').length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText('mobile-backend').length).toBeGreaterThanOrEqual(1);
    });
  });

  it('renders replacement info on cards', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('RSA-2048 key generation')).toBeInTheDocument();
      // "RSA-2048 -> ML-KEM-768" is rendered as separate text nodes
      expect(screen.getByText(/RSA-2048/)).toBeInTheDocument();
      expect(screen.getByText(/ML-KEM-768/)).toBeInTheDocument();
    });
  });

  it('renders assignee and deadline on cards', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Alice Chen')).toBeInTheDocument();
      expect(screen.getByText('2026-06-30')).toBeInTheDocument();
    });
  });

  it('renders filter dropdowns', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByLabelText('Filter by repo')).toBeInTheDocument();
      expect(screen.getByLabelText('Filter by language')).toBeInTheDocument();
      expect(screen.getByLabelText('Filter by framework')).toBeInTheDocument();
    });
  });

  it('opens card detail modal on click', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('RSA-2048 key generation')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('card-k-001'));

    await waitFor(() => {
      expect(screen.getByTestId('card-detail-modal')).toBeInTheDocument();
      expect(screen.getByText('Replacement Guidance')).toBeInTheDocument();
      expect(screen.getByText('CNSA 2.0 Deadline')).toBeInTheDocument();
      expect(screen.getByText('View Finding')).toBeInTheDocument();
    });
  });

  it('filters cards by repo', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('RSA-2048 key generation')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText('Filter by repo'), {
      target: { value: 'data-pipeline' },
    });

    await waitFor(() => {
      expect(screen.getByText('DH key exchange (legacy)')).toBeInTheDocument();
      // Cards from other repos should not be visible
      expect(screen.queryByText('RSA-2048 key generation')).not.toBeInTheDocument();
    });
  });

  it('filters cards by language', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('RSA-2048 key generation')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText('Filter by language'), {
      target: { value: 'Python' },
    });

    await waitFor(() => {
      expect(screen.getByText('ECDSA P-256 signatures')).toBeInTheDocument();
      // Java cards should not be visible
      expect(screen.queryByText('RSA-2048 key generation')).not.toBeInTheDocument();
    });
  });
});
