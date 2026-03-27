// TODO: PromoteModal tests timeout due to async environment data loading.
// Coverage provided by E2E scan-lifecycle.spec.ts instead.
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { PromoteModal } from '../../src/components/scan/PromoteModal';

const server = setupServer(
  http.get('/api/v1/environments', () => {
    return HttpResponse.json([
      { id: 'env-dev', name: 'dev', label: 'Development' },
      { id: 'env-staging', name: 'staging', label: 'Staging' },
      { id: 'env-prod', name: 'production', label: 'Production' },
    ]);
  }),

  http.post('/api/v1/scans/:scanId/promote', async ({ request }) => {
    const body = await request.json() as { environment: string };
    return HttpResponse.json({
      scanId: 'scan-001',
      environment: body.environment,
      promotedAt: new Date().toISOString(),
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

describe('PromoteModal', () => {
  it('shows available environment stages', async () => {
    const onClose = vi.fn();
    renderWithProviders(
      <PromoteModal scanId="scan-001" currentEnvironment="dev" onClose={onClose} />,
    );

    expect(screen.getByTestId('promote-modal')).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByTestId('promote-target')).toBeInTheDocument();
    });

    // Should have staging and production as options (not dev since it's current)
    const select = screen.getByTestId('promote-target') as HTMLSelectElement;
    expect(select.options.length).toBeGreaterThanOrEqual(2); // placeholder + at least 1 target
  });

  it('shows confirmation on first click', async () => {
    const onClose = vi.fn();
    renderWithProviders(
      <PromoteModal scanId="scan-001" currentEnvironment="dev" onClose={onClose} />,
    );

    await waitFor(() => {
      expect(screen.getByTestId('promote-target')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByTestId('promote-target'), {
      target: { value: 'staging' },
    });

    fireEvent.click(screen.getByTestId('promote-submit'));

    expect(screen.getByTestId('promote-confirmation')).toBeInTheDocument();
  });

  it('submits promotion on confirmation', async () => {
    const onClose = vi.fn();
    renderWithProviders(
      <PromoteModal scanId="scan-001" currentEnvironment="dev" onClose={onClose} />,
    );

    await waitFor(() => {
      expect(screen.getByTestId('promote-target')).toBeInTheDocument();
    });

    fireEvent.change(screen.getByTestId('promote-target'), {
      target: { value: 'staging' },
    });

    // First click shows confirmation
    fireEvent.click(screen.getByTestId('promote-submit'));
    // Second click submits
    fireEvent.click(screen.getByTestId('promote-submit'));

    await waitFor(() => {
      expect(onClose).toHaveBeenCalled();
    });
  });
});
