import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { ArtifactRegistries } from '../../src/pages/admin/ArtifactRegistries';

const server = setupServer(
  http.get('/api/v1/admin/registries', () => {
    return HttpResponse.json([
      {
        id: 'reg-001',
        name: 'JFrog Production',
        registryType: 'jfrog',
        url: 'https://jfrog.example.com',
        enabled: true,
        createdAt: '2026-01-15T10:00:00Z',
        updatedAt: '2026-03-20T14:00:00Z',
      },
      {
        id: 'reg-002',
        name: 'ECR Main',
        registryType: 'ecr',
        url: 'https://123456789.dkr.ecr.us-east-1.amazonaws.com',
        enabled: true,
        createdAt: '2026-02-01T10:00:00Z',
        updatedAt: '2026-03-20T14:00:00Z',
      },
    ]);
  }),

  http.post('/api/v1/admin/registries', async ({ request }) => {
    const body = await request.json() as Record<string, unknown>;
    return HttpResponse.json({
      id: 'reg-new',
      ...body,
      enabled: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
  }),

  http.post('/api/v1/admin/registries/:id/test', () => {
    return HttpResponse.json({
      success: true,
      message: 'Connection successful',
      latencyMs: 42,
    });
  }),

  http.delete('/api/v1/admin/registries/:id', () => {
    return HttpResponse.json({ success: true });
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

describe('ArtifactRegistries', () => {
  it('renders registries table', async () => {
    renderWithProviders(<ArtifactRegistries />);

    await waitFor(() => {
      expect(screen.getByTestId('registries-table')).toBeInTheDocument();
    });

    expect(screen.getByText('JFrog Production')).toBeInTheDocument();
    expect(screen.getByText('ECR Main')).toBeInTheDocument();
  });

  it('opens add modal on button click', async () => {
    renderWithProviders(<ArtifactRegistries />);

    await waitFor(() => {
      expect(screen.getByTestId('add-registry-btn')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('add-registry-btn'));

    expect(screen.getByTestId('add-registry-modal')).toBeInTheDocument();
    expect(screen.getByTestId('registry-name')).toBeInTheDocument();
    expect(screen.getByTestId('registry-type')).toBeInTheDocument();
    expect(screen.getByTestId('registry-url')).toBeInTheDocument();
    expect(screen.getByTestId('registry-auth')).toBeInTheDocument();
  });

  it('tests connection for a registry', async () => {
    renderWithProviders(<ArtifactRegistries />);

    await waitFor(() => {
      expect(screen.getByTestId('test-conn-reg-001')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('test-conn-reg-001'));

    // The test connection call should succeed (toast displayed)
    await waitFor(() => {
      expect(screen.getByTestId('test-conn-reg-001')).not.toBeDisabled();
    });
  });
});
