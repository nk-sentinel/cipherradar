import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { ScanModal } from '../../src/components/scan/ScanModal';

const server = setupServer(
  http.post('/api/v1/projects/:projectId/scans/trigger', async ({ request }) => {
    const body = await request.json() as Record<string, unknown>;
    return HttpResponse.json({
      status: 'queued',
      scanId: 'scan-test-123',
      sourceType: body.sourceType,
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

describe('ScanModal', () => {
  it('renders three source tabs', () => {
    const onClose = vi.fn();
    renderWithProviders(
      <ScanModal context="dashboard" onClose={onClose} />,
    );

    expect(screen.getByTestId('scan-modal')).toBeInTheDocument();
    expect(screen.getByTestId('tab-repository')).toBeInTheDocument();
    expect(screen.getByTestId('tab-container')).toBeInTheDocument();
    expect(screen.getByTestId('tab-artifact')).toBeInTheDocument();
  });

  it('shows branch selector on repository tab', () => {
    const onClose = vi.fn();
    renderWithProviders(
      <ScanModal context="dashboard" onClose={onClose} />,
    );

    // Repository tab is default
    expect(screen.getByTestId('branch-selector')).toBeInTheDocument();
    expect(screen.getByTestId('policy-selector')).toBeInTheDocument();
  });

  it('prefills project when context is project-row', () => {
    const onClose = vi.fn();
    renderWithProviders(
      <ScanModal context="project-row" projectId="proj-001" onClose={onClose} />,
    );

    const projectInput = screen.getByTestId('project-id-display');
    expect(projectInput).toHaveTextContent('proj-001');
  });

  it('submits triggers API call', async () => {
    const onClose = vi.fn();
    renderWithProviders(
      <ScanModal context="project-row" projectId="proj-001" onClose={onClose} />,
    );

    fireEvent.click(screen.getByTestId('scan-submit'));

    await waitFor(() => {
      expect(onClose).toHaveBeenCalled();
    });
  });

  it('shows upload area on artifact tab', () => {
    const onClose = vi.fn();
    renderWithProviders(
      <ScanModal context="dashboard" onClose={onClose} />,
    );

    fireEvent.click(screen.getByTestId('tab-artifact'));
    expect(screen.getByTestId('artifact-version')).toBeInTheDocument();
  });

  it('shows container tag selector on container tab', () => {
    const onClose = vi.fn();
    renderWithProviders(
      <ScanModal context="dashboard" onClose={onClose} />,
    );

    fireEvent.click(screen.getByTestId('tab-container'));
    expect(screen.getByTestId('container-tag')).toBeInTheDocument();
  });

  it('shows simplified view for project-overview context', () => {
    const onClose = vi.fn();
    renderWithProviders(
      <ScanModal context="project-overview" projectId="proj-001" onClose={onClose} />,
    );

    expect(screen.getByTestId('branch-selector')).toBeInTheDocument();
    expect(screen.getByTestId('more-options-btn')).toBeInTheDocument();
  });

  it('expands to full view from project-overview when More Options clicked', () => {
    const onClose = vi.fn();
    renderWithProviders(
      <ScanModal context="project-overview" projectId="proj-001" onClose={onClose} />,
    );

    fireEvent.click(screen.getByTestId('more-options-btn'));

    expect(screen.getByTestId('tab-repository')).toBeInTheDocument();
    expect(screen.getByTestId('tab-container')).toBeInTheDocument();
    expect(screen.getByTestId('tab-artifact')).toBeInTheDocument();
  });
});
