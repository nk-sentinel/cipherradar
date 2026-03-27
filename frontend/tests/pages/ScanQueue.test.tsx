import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { ScanQueue } from '../../src/pages/ScanQueue';

const MOCK_SCANS = [
  {
    id: 'scan-001',
    projectName: 'auth-service',
    projectId: 'proj-001',
    triggerType: 'manual',
    status: 'completed',
    startedAt: '2026-03-27T10:00:00Z',
    duration: '2m 15s',
    triggeredBy: 'alice@example.com',
  },
  {
    id: 'scan-002',
    projectName: 'payment-api',
    projectId: 'proj-002',
    triggerType: 'schedule',
    status: 'running',
    startedAt: '2026-03-27T11:00:00Z',
    duration: null,
    triggeredBy: 'cron',
  },
  {
    id: 'scan-003',
    projectName: 'frontend-app',
    projectId: 'proj-003',
    triggerType: 'webhook',
    status: 'queued',
    startedAt: '2026-03-27T11:05:00Z',
    duration: null,
    triggeredBy: 'github-webhook',
  },
];

const server = setupServer(
  http.get('/api/v1/scans', ({ request }) => {
    const url = new URL(request.url);
    const status = url.searchParams.get('status');
    let filtered = MOCK_SCANS;
    if (status) {
      filtered = MOCK_SCANS.filter((s) => s.status === status);
    }
    return HttpResponse.json({
      items: filtered,
      total: filtered.length,
      page: 1,
      perPage: 25,
    });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderWithProviders(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
  );
}

describe('ScanQueue', () => {
  it('renders the scan queue table', async () => {
    renderWithProviders(<ScanQueue />);

    await waitFor(() => {
      expect(screen.getByTestId('scan-queue-table')).toBeInTheDocument();
    });

    expect(screen.getByText('auth-service')).toBeInTheDocument();
    expect(screen.getByText('payment-api')).toBeInTheDocument();
    expect(screen.getByText('frontend-app')).toBeInTheDocument();
  });

  it('filters by status', async () => {
    renderWithProviders(<ScanQueue />);

    await waitFor(() => {
      expect(screen.getByTestId('scan-queue-table')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByTestId('filter-status'), {
      target: { value: 'running' },
    });

    await waitFor(() => {
      expect(screen.getByText('payment-api')).toBeInTheDocument();
    });
  });

  it('shows filter dropdowns', () => {
    renderWithProviders(<ScanQueue />);

    expect(screen.getByTestId('filter-status')).toBeInTheDocument();
    expect(screen.getByTestId('filter-trigger')).toBeInTheDocument();
  });
});
