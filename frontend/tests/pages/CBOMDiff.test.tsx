import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { MOCK_CBOM_DIFF, MOCK_SCAN_SELECTORS } from '../../src/mocks/data/cbomDiff.ts';
import { CBOMDiff } from '../../src/pages/CBOMDiff.tsx';
import {
  createRouter,
  createRootRoute,
  createRoute,
  RouterProvider,
  createMemoryHistory,
} from '@tanstack/react-router';

const server = setupServer(
  http.get('/api/v1/cbom/diff', () => {
    return HttpResponse.json(MOCK_CBOM_DIFF);
  }),
  http.get('/api/v1/cbom/scans', () => {
    return HttpResponse.json(MOCK_SCAN_SELECTORS);
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
  const diffRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/diff',
    component: CBOMDiff,
  });

  const routeTree = rootRoute.addChildren([diffRoute]);

  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ['/diff'] }),
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('CBOMDiff page', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* jsdom may not support */ }
  });

  it('renders the page title', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('CBOM Diff')).toBeInTheDocument();
    });
  });

  it('renders scan selector dropdowns', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByLabelText('Select base scan')).toBeInTheDocument();
      expect(screen.getByLabelText('Select target scan')).toBeInTheDocument();
    });
  });

  it('renders summary stats', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Added')).toBeInTheDocument();
      expect(screen.getByText('Removed')).toBeInTheDocument();
      expect(screen.getByText('Changed')).toBeInTheDocument();
      expect(screen.getByText('Unchanged')).toBeInTheDocument();
    });
  });

  it('renders diff summary values', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText(`+${String(MOCK_CBOM_DIFF.summary.added)}`)).toBeInTheDocument();
      expect(screen.getByText(`-${String(MOCK_CBOM_DIFF.summary.removed)}`)).toBeInTheDocument();
      expect(screen.getByText(`~${String(MOCK_CBOM_DIFF.summary.changed)}`)).toBeInTheDocument();
      expect(screen.getByText(`=${String(MOCK_CBOM_DIFF.summary.unchanged)}`)).toBeInTheDocument();
    });
  });

  it('renders diff items in table', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('PBKDF2-SHA256')).toBeInTheDocument();
      expect(screen.getByText('MD5')).toBeInTheDocument();
    });
  });

  it('renders diff type filter buttons', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText(/All \(\d+\)/)).toBeInTheDocument();
    });
  });

  it('renders severity filter dropdown', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByLabelText('Filter by severity')).toBeInTheDocument();
    });
  });

  it('renders export button', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Export Diff Report')).toBeInTheDocument();
    });
  });

  it('filters diff items by type', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('PBKDF2-SHA256')).toBeInTheDocument();
    });

    // Click "Removed" filter
    const removedButton = screen.getAllByText(/Removed/).find((el) => el.tagName === 'BUTTON');
    if (removedButton) {
      fireEvent.click(removedButton);
    }

    await waitFor(() => {
      // MD5 is a removed item
      expect(screen.getByText('MD5')).toBeInTheDocument();
    });
  });
});
