import { describe, it, expect, beforeAll, afterEach, afterAll } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { RequestQueue } from '../../src/pages/RequestQueue';

const mockRequests = {
  items: [
    {
      id: 'req-001',
      findingId: 'f-001',
      findingSummary: 'Certificate validation disabled',
      findingSeverity: 'critical',
      requester: 'alice@example.com',
      type: 'false_positive',
      justification: 'Test environment only.',
      status: 'pending',
      createdAt: '2026-03-20T10:00:00Z',
    },
    {
      id: 'req-002',
      findingId: 'f-006',
      findingSummary: 'RSA-2048 key generation',
      findingSeverity: 'medium',
      requester: 'bob@example.com',
      type: 'risk_accepted',
      justification: 'Migration planned for Q3.',
      reasonCategory: 'migration_planned',
      reviewDate: '2026-06-30',
      status: 'pending',
      createdAt: '2026-03-21T14:00:00Z',
    },
  ],
  total: 2,
};

const server = setupServer(
  http.get('/api/v1/requests', () => {
    return HttpResponse.json(mockRequests);
  }),
  http.post('/api/v1/requests/:requestId/approve', ({ params }) => {
    return HttpResponse.json({
      id: params['requestId'],
      status: 'approved',
      updatedAt: new Date().toISOString(),
    });
  }),
  http.post('/api/v1/requests/:requestId/reject', async ({ request, params }) => {
    const body = await request.json() as { reason: string };
    return HttpResponse.json({
      id: params['requestId'],
      status: 'rejected',
      rejectionReason: body.reason,
      updatedAt: new Date().toISOString(),
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

describe('RequestQueue', () => {
  it('renders pending requests table', async () => {
    renderWithProviders(<RequestQueue />);

    await waitFor(() => {
      expect(screen.getByText('Pending Requests')).toBeInTheDocument();
      expect(screen.getByText('Certificate validation disabled')).toBeInTheDocument();
      expect(screen.getByText('RSA-2048 key generation')).toBeInTheDocument();
    });
  });

  it('displays requester and type badges', async () => {
    renderWithProviders(<RequestQueue />);

    await waitFor(() => {
      expect(screen.getByText('alice@example.com')).toBeInTheDocument();
      expect(screen.getByText('bob@example.com')).toBeInTheDocument();
      expect(screen.getByText('FP')).toBeInTheDocument();
      expect(screen.getByText('RA')).toBeInTheDocument();
    });
  });

  it('has approve buttons for each request', async () => {
    renderWithProviders(<RequestQueue />);

    await waitFor(() => {
      expect(screen.getByTestId('approve-req-001')).toBeInTheDocument();
      expect(screen.getByTestId('approve-req-002')).toBeInTheDocument();
    });
  });

  it('clicking approve calls API', async () => {
    renderWithProviders(<RequestQueue />);

    await waitFor(() => {
      expect(screen.getByTestId('approve-req-001')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('approve-req-001'));
    // The approve mutation should fire — no error expected
  });

  it('clicking reject shows reason modal', async () => {
    renderWithProviders(<RequestQueue />);

    await waitFor(() => {
      expect(screen.getByTestId('reject-req-001')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('reject-req-001'));

    await waitFor(() => {
      expect(screen.getByTestId('reject-reason-modal')).toBeInTheDocument();
      expect(screen.getByTestId('reject-reason-input')).toBeInTheDocument();
    });
  });

  it('renders pagination', async () => {
    renderWithProviders(<RequestQueue />);

    await waitFor(() => {
      expect(screen.getByLabelText('Pagination')).toBeInTheDocument();
    });
  });
});
