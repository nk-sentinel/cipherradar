import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { MOCK_GRAPH_DATA } from '../../src/mocks/data/graph.ts';
import { DependencyGraph } from '../../src/pages/DependencyGraph.tsx';
import {
  createRouter,
  createRootRoute,
  createRoute,
  RouterProvider,
  createMemoryHistory,
} from '@tanstack/react-router';

const server = setupServer(
  http.get('/api/v1/graph', () => {
    return HttpResponse.json(MOCK_GRAPH_DATA);
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
  const graphRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/graph',
    component: DependencyGraph,
  });

  const routeTree = rootRoute.addChildren([graphRoute]);

  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ['/graph'] }),
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('DependencyGraph page', () => {
  beforeEach(() => {
    // Mock canvas context for jsdom
    HTMLCanvasElement.prototype.getContext = (() => {
      return {
        save: () => {},
        restore: () => {},
        clearRect: () => {},
        translate: () => {},
        scale: () => {},
        beginPath: () => {},
        arc: () => {},
        rect: () => {},
        moveTo: () => {},
        lineTo: () => {},
        closePath: () => {},
        fill: () => {},
        stroke: () => {},
        fillText: () => {},
        measureText: () => ({ width: 0 }),
        fillStyle: '',
        strokeStyle: '',
        lineWidth: 1,
        globalAlpha: 1,
        font: '',
        textAlign: '',
      };
    }) as unknown as typeof HTMLCanvasElement.prototype.getContext;
    try { sessionStorage.clear(); } catch { /* jsdom may not support */ }
  });

  it('renders the page title', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Crypto Dependency Graph')).toBeInTheDocument();
    });
  });

  it('renders filter dropdowns', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByLabelText('Filter by language')).toBeInTheDocument();
      expect(screen.getByLabelText('Filter by quantum status')).toBeInTheDocument();
    });
  });

  it('renders the legend', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('QUANTUM STATUS:')).toBeInTheDocument();
      expect(screen.getByText('NODE TYPE:')).toBeInTheDocument();
    });
  });

  it('renders node detail panel placeholder', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Node Detail')).toBeInTheDocument();
      expect(screen.getByText('Click a node in the graph to view details.')).toBeInTheDocument();
    });
  });

  it('renders node/edge count', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText(/nodes.*edges/)).toBeInTheDocument();
    });
  });
});
