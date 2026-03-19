import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { MOCK_REPOSITORIES } from '../../src/mocks/data/repositories.ts';
import { Repositories } from '../../src/pages/Repositories.tsx';
import {
  createRouter,
  createRootRoute,
  createRoute,
  RouterProvider,
  createMemoryHistory,
} from '@tanstack/react-router';

const server = setupServer(
  http.get('/api/v1/projects', () => {
    return HttpResponse.json(MOCK_REPOSITORIES);
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
  const reposRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/repos',
    component: Repositories,
  });

  const routeTree = rootRoute.addChildren([reposRoute]);

  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ['/repos'] }),
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('Repositories page', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* jsdom may not support */ }
  });

  it('renders the page title and connect button', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Repositories')).toBeInTheDocument();
      expect(screen.getByText('+ Connect Repo')).toBeInTheDocument();
    });
  });

  it('renders repository rows from mock data', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('payment-service')).toBeInTheDocument();
      expect(screen.getByText('auth-api')).toBeInTheDocument();
      expect(screen.getByText('data-pipeline')).toBeInTheDocument();
      expect(screen.getByText('mobile-backend')).toBeInTheDocument();
    });
  });

  it('shows provider for each repo', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('payment-service')).toBeInTheDocument();
      expect(screen.getAllByText('GitHub')).toHaveLength(2);
      expect(screen.getByText('GitLab')).toBeInTheDocument();
      expect(screen.getByText('Bitbucket')).toBeInTheDocument();
    });
  });

  it('shows compliance percentages', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('payment-service')).toBeInTheDocument();
      expect(screen.getByText('65%')).toBeInTheDocument();
      expect(screen.getByText('82%')).toBeInTheDocument();
      expect(screen.getByText('94%')).toBeInTheDocument();
      expect(screen.getByText('45%')).toBeInTheDocument();
    });
  });

  it('renders search input', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Search...')).toBeInTheDocument();
    });
  });

  it('renders scan buttons', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('payment-service')).toBeInTheDocument();
      const scanButtons = screen.getAllByText('Scan');
      expect(scanButtons.length).toBe(4);
    });
  });
});
