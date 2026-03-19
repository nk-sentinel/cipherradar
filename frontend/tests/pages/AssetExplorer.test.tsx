import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { searchAssets } from '../../src/mocks/data/assets.ts';
import type { AssetFilters, AssetType, QuantumAssetStatus, ComplianceTag } from '../../src/mocks/data/assets.ts';
import { AssetExplorer } from '../../src/pages/AssetExplorer.tsx';
import {
  createRouter,
  createRootRoute,
  createRoute,
  RouterProvider,
  createMemoryHistory,
} from '@tanstack/react-router';

const server = setupServer(
  http.get('/api/v1/assets', ({ request }) => {
    const url = new URL(request.url);
    const filters: AssetFilters = {};
    const typeParam = url.searchParams.get('type');
    if (typeParam) filters.type = typeParam as AssetType;
    const lang = url.searchParams.get('language');
    if (lang) filters.language = lang;
    const qs = url.searchParams.get('quantumStatus');
    if (qs) filters.quantumStatus = qs as QuantumAssetStatus;
    const comp = url.searchParams.get('compliance');
    if (comp) filters.compliance = comp as ComplianceTag;
    const search = url.searchParams.get('search');
    if (search) filters.search = search;

    const page = Number(url.searchParams.get('page') || '1');
    const pageSize = Number(url.searchParams.get('pageSize') || '15');

    return HttpResponse.json(searchAssets(filters, page, pageSize));
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
  const assetsRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/assets',
    component: AssetExplorer,
  });

  const routeTree = rootRoute.addChildren([assetsRoute]);

  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ['/assets'] }),
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('AssetExplorer page', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* jsdom may not support */ }
  });

  it('renders the page title', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Asset Explorer')).toBeInTheDocument();
    });
  });

  it('renders the asset table with column headers', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Asset Name')).toBeInTheDocument();
      expect(screen.getByText('Type')).toBeInTheDocument();
      expect(screen.getByText('Language')).toBeInTheDocument();
      expect(screen.getByText('Repository')).toBeInTheDocument();
      expect(screen.getByText('File:Line')).toBeInTheDocument();
      expect(screen.getByText('Quantum Status')).toBeInTheDocument();
    });
  });

  it('renders the search input', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Search assets...')).toBeInTheDocument();
    });
  });

  it('renders filter dropdowns', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByLabelText('Filter by type')).toBeInTheDocument();
      expect(screen.getByLabelText('Filter by language')).toBeInTheDocument();
      expect(screen.getByLabelText('Filter by quantum status')).toBeInTheDocument();
      expect(screen.getByLabelText('Filter by compliance')).toBeInTheDocument();
    });
  });

  it('renders asset rows from mock data', async () => {
    renderWithProviders();
    await waitFor(() => {
      // First page should contain AES-256-GCM (first asset)
      expect(screen.getAllByText('AES-256-GCM').length).toBeGreaterThanOrEqual(1);
    });
  });

  it('renders export CSV button', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Export CSV')).toBeInTheDocument();
    });
  });

  it('shows total count of assets', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('60 assets found')).toBeInTheDocument();
    });
  });

  it('renders pagination controls', async () => {
    renderWithProviders();
    await waitFor(() => {
      // With 60 assets and 15 per page, we should have 4 pages
      expect(screen.getByText('Prev')).toBeInTheDocument();
      expect(screen.getByText('Next')).toBeInTheDocument();
    });
  });

  it('filters assets by search input', async () => {
    renderWithProviders();

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Search assets...')).toBeInTheDocument();
    });

    const searchInput = screen.getByPlaceholderText('Search assets...');
    fireEvent.change(searchInput, { target: { value: 'MD5' } });

    await waitFor(() => {
      expect(screen.getByText('2 assets found')).toBeInTheDocument();
    });
  });
});
