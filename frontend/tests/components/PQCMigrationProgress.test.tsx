import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { PQCMigrationProgress } from '../../src/components/compliance/PQCMigrationProgress.tsx';

const MOCK_PQC_DATA = {
  overview: {
    totalFindings: 100,
    vulnerable: 40,
    safe: 45,
    unknown: 15,
    percentVulnerable: 40.0,
    percentSafe: 45.0,
    percentUnknown: 15.0,
  },
  families: [
    { family: 'RSA', total: 30, vulnerable: 20, safe: 5, unknown: 5, percentMigrated: 16.67 },
    { family: 'ECDSA', total: 25, vulnerable: 15, safe: 8, unknown: 2, percentMigrated: 32.0 },
    { family: 'AES', total: 20, vulnerable: 0, safe: 18, unknown: 2, percentMigrated: 90.0 },
    { family: 'SHA-2', total: 15, vulnerable: 0, safe: 14, unknown: 1, percentMigrated: 93.33 },
    { family: 'DES', total: 10, vulnerable: 5, safe: 0, unknown: 5, percentMigrated: 0.0 },
  ],
  laggingProjects: [
    { projectId: 'proj-001', projectName: 'payment-service', vulnerableCount: 15, totalCount: 20, percentVulnerable: 75.0 },
    { projectId: 'proj-002', projectName: 'auth-api', vulnerableCount: 10, totalCount: 30, percentVulnerable: 33.33 },
    { projectId: 'proj-003', projectName: 'data-pipeline', vulnerableCount: 8, totalCount: 25, percentVulnerable: 32.0 },
  ],
};

const server = setupServer(
  http.get('/api/v1/portfolio/pqc-migration', () => {
    return HttpResponse.json(MOCK_PQC_DATA);
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

  return render(
    <QueryClientProvider client={queryClient}>
      <PQCMigrationProgress />
    </QueryClientProvider>,
  );
}

describe('PQCMigrationProgress component', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* jsdom may not support */ }
  });

  it('renders the donut chart section', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('PQC Migration Progress')).toBeInTheDocument();
      expect(screen.getByText('40%')).toBeInTheDocument();  // percent vulnerable
    });
  });

  it('renders algorithm family progress bars', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('RSA')).toBeInTheDocument();
      expect(screen.getByText('ECDSA')).toBeInTheDocument();
      expect(screen.getByText('AES')).toBeInTheDocument();
    });
  });

  it('renders lagging projects list', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Lagging Projects')).toBeInTheDocument();
      expect(screen.getByText('payment-service')).toBeInTheDocument();
      expect(screen.getByText('auth-api')).toBeInTheDocument();
      expect(screen.getByText('data-pipeline')).toBeInTheDocument();
    });
  });
});
