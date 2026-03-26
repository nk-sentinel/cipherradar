import { describe, it, expect, vi, beforeAll, afterEach, afterAll } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { BulkActionBar } from '../../src/components/findings/BulkActionBar';

// Mock useAuth to control role
const mockUseAuth = vi.fn();
vi.mock('../../src/lib/auth', () => ({
  useAuth: () => mockUseAuth(),
}));

const server = setupServer(
  http.post('/api/v1/findings/bulk', async ({ request }) => {
    const body = await request.json() as { findingIds: string[]; action: string };
    return HttpResponse.json({
      affected: body.findingIds.length,
      action: body.action,
      updatedAt: new Date().toISOString(),
    });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }));
afterEach(() => {
  server.resetHandlers();
  vi.clearAllMocks();
});
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

describe('BulkActionBar', () => {
  it('appears when findings are selected', () => {
    mockUseAuth.mockReturnValue({
      user: { email: 'admin@example.com', role: 'org-admin', name: 'Admin', initials: 'A' },
    });

    const onClear = vi.fn();
    renderWithProviders(
      <BulkActionBar selectedIds={['f-001', 'f-002']} onClear={onClear} />,
    );

    expect(screen.getByTestId('bulk-action-bar')).toBeInTheDocument();
    expect(screen.getByTestId('bulk-count')).toHaveTextContent('2 selected');
  });

  it('does not render when no findings selected', () => {
    mockUseAuth.mockReturnValue({
      user: { email: 'admin@example.com', role: 'org-admin', name: 'Admin', initials: 'A' },
    });

    const onClear = vi.fn();
    const { container } = renderWithProviders(
      <BulkActionBar selectedIds={[]} onClear={onClear} />,
    );

    expect(container.innerHTML).toBe('');
  });

  it('filters available actions by role — org-admin sees all', () => {
    mockUseAuth.mockReturnValue({
      user: { email: 'admin@example.com', role: 'org-admin', name: 'Admin', initials: 'A' },
    });

    const onClear = vi.fn();
    renderWithProviders(
      <BulkActionBar selectedIds={['f-001']} onClear={onClear} />,
    );

    expect(screen.getByTestId('bulk-assign')).toBeInTheDocument();
    expect(screen.getByTestId('bulk-status')).toBeInTheDocument();
    expect(screen.getByTestId('bulk-more')).toBeInTheDocument();
  });

  it('filters available actions by role — developer sees limited actions', () => {
    mockUseAuth.mockReturnValue({
      user: { email: 'dev@example.com', role: 'developer', name: 'Dev', initials: 'D' },
    });

    const onClear = vi.fn();
    renderWithProviders(
      <BulkActionBar selectedIds={['f-001']} onClear={onClear} />,
    );

    // Developer should NOT see assign or status
    expect(screen.queryByTestId('bulk-assign')).not.toBeInTheDocument();
    expect(screen.queryByTestId('bulk-status')).not.toBeInTheDocument();
    // Developer should see More with raise_fp_request and export
    expect(screen.getByTestId('bulk-more')).toBeInTheDocument();
  });

  it('clear button calls onClear', () => {
    mockUseAuth.mockReturnValue({
      user: { email: 'admin@example.com', role: 'org-admin', name: 'Admin', initials: 'A' },
    });

    const onClear = vi.fn();
    renderWithProviders(
      <BulkActionBar selectedIds={['f-001']} onClear={onClear} />,
    );

    fireEvent.click(screen.getByTestId('bulk-clear'));
    expect(onClear).toHaveBeenCalled();
  });

  it('guest role sees no actions', () => {
    mockUseAuth.mockReturnValue({
      user: { email: 'guest@example.com', role: 'guest', name: 'Guest', initials: 'G' },
    });

    const onClear = vi.fn();
    renderWithProviders(
      <BulkActionBar selectedIds={['f-001']} onClear={onClear} />,
    );

    expect(screen.queryByTestId('bulk-assign')).not.toBeInTheDocument();
    expect(screen.queryByTestId('bulk-status')).not.toBeInTheDocument();
    expect(screen.queryByTestId('bulk-more')).not.toBeInTheDocument();
  });
});
