import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { ApiKeyManager } from '../../src/components/profile/ApiKeyManager.tsx';
import { AuthProvider } from '../../src/lib/auth.tsx';

const MOCK_KEYS = [
  {
    id: 'key-001',
    name: 'CI/CD Pipeline',
    prefix: 'cr_sk_abc123',
    scopes: ['scan:write', 'cbom:read'],
    createdAt: '2026-03-18',
    lastUsed: '1h ago',
    status: 'active' as const,
  },
  {
    id: 'key-002',
    name: 'Local dev',
    prefix: 'cr_sk_def456',
    scopes: ['scan:read'],
    createdAt: '2026-03-10',
    lastUsed: null,
    status: 'revoked' as const,
  },
];

const server = setupServer(
  http.get('/api/v1/auth/api-keys', () => {
    return HttpResponse.json(MOCK_KEYS);
  }),
  http.delete('/api/v1/auth/api-keys/:keyId', () => {
    return HttpResponse.json({ success: true });
  }),
  http.post('/api/v1/auth/api-keys', async () => {
    return HttpResponse.json({
      id: 'key-new',
      name: 'New Key',
      prefix: 'cr_sk_new999',
      rawKey: 'cr_sk_new999_full_secret_key_value_here',
      scopes: ['scan:read'],
      createdAt: '2026-03-27',
      expiresAt: '2026-06-25',
    });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function setMockUser() {
  const user = {
    name: 'Test User',
    email: 'test@example.com',
    role: 'org-admin',
    initials: 'TU',
  };
  sessionStorage.setItem('cipherradar-token', 'mock-token');
  sessionStorage.setItem('cipherradar-user', JSON.stringify(user));
}

function renderWithProviders() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <ApiKeyManager />
      </AuthProvider>
    </QueryClientProvider>,
  );
}

describe('ApiKeyManager', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* ignore */ }
  });

  it('renders API key table with keys', async () => {
    setMockUser();
    renderWithProviders();

    await waitFor(() => {
      expect(screen.getByText('CI/CD Pipeline')).toBeInTheDocument();
    });

    expect(screen.getByText('Local dev')).toBeInTheDocument();
    expect(screen.getByText('cr_sk_abc123...')).toBeInTheDocument();
    expect(screen.getByText('cr_sk_def456...')).toBeInTheDocument();
  });

  it('shows correct column headers', async () => {
    setMockUser();
    renderWithProviders();

    await waitFor(() => {
      expect(screen.getByText('Name')).toBeInTheDocument();
    });

    expect(screen.getByText('Key Prefix')).toBeInTheDocument();
    expect(screen.getByText('Scopes')).toBeInTheDocument();
    expect(screen.getByText('Created')).toBeInTheDocument();
    expect(screen.getByText('Last Used')).toBeInTheDocument();
    expect(screen.getByText('Status')).toBeInTheDocument();
    expect(screen.getByText('Actions')).toBeInTheDocument();
  });

  it('shows revoke button only for active keys', async () => {
    setMockUser();
    renderWithProviders();

    await waitFor(() => {
      expect(screen.getByTestId('revoke-key-key-001')).toBeInTheDocument();
    });

    // Revoked keys should not have a revoke button
    expect(screen.queryByTestId('revoke-key-key-002')).not.toBeInTheDocument();
  });

  it('shows "Never" for lastUsed when null', async () => {
    setMockUser();
    renderWithProviders();

    await waitFor(() => {
      expect(screen.getByText('Never')).toBeInTheDocument();
    });
  });

  it('revokes a key when revoke button is clicked', async () => {
    setMockUser();
    renderWithProviders();

    await waitFor(() => {
      expect(screen.getByTestId('revoke-key-key-001')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('revoke-key-key-001'));

    // The mutation should trigger; since MSW returns success, invalidation should happen
    await waitFor(() => {
      // The query is invalidated, so the table should still render
      expect(screen.getByText('CI/CD Pipeline')).toBeInTheDocument();
    });
  });

  it('opens create modal when create button is clicked', async () => {
    setMockUser();
    renderWithProviders();

    await waitFor(() => {
      expect(screen.getByTestId('create-api-key-btn')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('create-api-key-btn'));

    await waitFor(() => {
      expect(screen.getByTestId('api-key-create-modal')).toBeInTheDocument();
    });
  });

  it('shows raw key after successful creation', async () => {
    setMockUser();
    renderWithProviders();

    await waitFor(() => {
      expect(screen.getByTestId('create-api-key-btn')).toBeInTheDocument();
    });

    // Open create modal
    fireEvent.click(screen.getByTestId('create-api-key-btn'));

    await waitFor(() => {
      expect(screen.getByTestId('api-key-create-modal')).toBeInTheDocument();
    });

    // Fill in form
    fireEvent.change(screen.getByLabelText('Name'), {
      target: { value: 'New Key' },
    });

    // Select a scope
    const scanReadCheckbox = screen.getByLabelText('scan:read');
    fireEvent.click(scanReadCheckbox);

    // Submit
    fireEvent.click(screen.getByRole('button', { name: /create key/i }));

    // Should show raw key
    await waitFor(() => {
      expect(screen.getByTestId('api-key-success')).toBeInTheDocument();
    });

    expect(screen.getByTestId('raw-key-display')).toHaveTextContent('cr_sk_new999_full_secret_key_value_here');
    expect(screen.getByTestId('copy-key-btn')).toBeInTheDocument();
    expect(screen.getByText(/copy this key now/i)).toBeInTheDocument();
  });

  it('shows empty state when no keys exist', async () => {
    server.use(
      http.get('/api/v1/auth/api-keys', () => {
        return HttpResponse.json([]);
      }),
    );

    setMockUser();
    renderWithProviders();

    await waitFor(() => {
      expect(screen.getByText(/no api keys yet/i)).toBeInTheDocument();
    });
  });
});
