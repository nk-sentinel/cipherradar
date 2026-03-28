import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { AdminApiKeys } from '../../src/pages/admin/AdminApiKeys.tsx';
import { AuthProvider } from '../../src/lib/auth.tsx';
import { OrgProvider } from '../../src/lib/org-context.tsx';
import { MOCK_ORGS } from '../../src/mocks/data/admin.ts';
import {
  createRouter,
  createRootRoute,
  createRoute,
  RouterProvider,
  createMemoryHistory,
} from '@tanstack/react-router';

const MOCK_ADMIN_API_KEYS = {
  items: [
    {
      id: 'key-001',
      name: 'CI Pipeline',
      keyPrefix: 'cbom_sk_xxxx',
      owner: 'alex.chen@nk-sentinel.io',
      scopes: ['scan:read', 'scan:write'],
      createdAt: '2026-03-15T10:00:00Z',
      expiresAt: null,
      lastUsedAt: '2026-03-27T08:00:00Z',
      revokedAt: null,
      status: 'active',
    },
    {
      id: 'key-002',
      name: 'Read-only Dashboard',
      keyPrefix: 'cbom_sk_yyyy',
      owner: 'sarah.kim@nk-sentinel.io',
      scopes: ['scan:read'],
      createdAt: '2026-03-20T14:00:00Z',
      expiresAt: '2026-06-20T14:00:00Z',
      lastUsedAt: null,
      revokedAt: null,
      status: 'active',
    },
    {
      id: 'key-003',
      name: 'Stale Key',
      keyPrefix: 'cbom_sk_zzzz',
      owner: 'alex.chen@nk-sentinel.io',
      scopes: ['scan:read', 'cbom:read'],
      createdAt: '2026-01-10T10:00:00Z',
      expiresAt: null,
      lastUsedAt: '2026-01-15T08:00:00Z',
      revokedAt: null,
      status: 'active',
    },
    {
      id: 'key-004',
      name: 'Revoked Key',
      keyPrefix: 'cbom_sk_rrrr',
      owner: 'james.liu@nk-sentinel.io',
      scopes: ['scan:read'],
      createdAt: '2026-02-01T10:00:00Z',
      expiresAt: null,
      lastUsedAt: '2026-02-15T08:00:00Z',
      revokedAt: '2026-03-01T10:00:00Z',
      status: 'revoked',
    },
  ],
  total: 4,
};

const server = setupServer(
  http.get('/api/v1/admin/api-keys', () => {
    return HttpResponse.json(MOCK_ADMIN_API_KEYS);
  }),
  http.get('/api/v1/user/orgs', () => {
    return HttpResponse.json(MOCK_ORGS);
  }),
  http.delete('/api/v1/admin/api-keys/:keyId', () => {
    return HttpResponse.json({ message: 'API key revoked successfully' });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function setMockUser(role: string) {
  const user = {
    name: 'Test Admin',
    email: 'admin@example.com',
    role,
    initials: 'TA',
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

  const rootRoute = createRootRoute();
  const apiKeysRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/admin/api-keys',
    component: AdminApiKeys,
  });
  const dashRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/',
    component: () => <div>Dashboard</div>,
  });

  const routeTree = rootRoute.addChildren([apiKeysRoute, dashRoute]);

  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ['/admin/api-keys'] }),
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <OrgProvider orgs={MOCK_ORGS}>
          <RouterProvider router={router} />
        </OrgProvider>
      </AuthProvider>
    </QueryClientProvider>,
  );
}

describe('AdminApiKeys page', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* jsdom may not support */ }
    try { localStorage.clear(); } catch { /* jsdom may not support */ }
  });

  it('renders page title for org-admin', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('API Keys')).toBeInTheDocument();
    });
  });

  it('renders table headers', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Name')).toBeInTheDocument();
      expect(screen.getByText('Owner')).toBeInTheDocument();
      expect(screen.getByText('Scopes')).toBeInTheDocument();
      expect(screen.getByText('Created')).toBeInTheDocument();
      expect(screen.getByText('Last Used')).toBeInTheDocument();
      expect(screen.getByText('Status')).toBeInTheDocument();
      expect(screen.getByText('Actions')).toBeInTheDocument();
    });
  });

  it('renders API key rows', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('CI Pipeline')).toBeInTheDocument();
      expect(screen.getByText('Read-only Dashboard')).toBeInTheDocument();
      expect(screen.getByText('Stale Key')).toBeInTheDocument();
      expect(screen.getByText('Revoked Key')).toBeInTheDocument();
    });
  });

  it('shows key count', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('4 keys')).toBeInTheDocument();
    });
  });

  it('shows stale indicator for keys unused 30+ days', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByTestId('stale-indicator-key-003')).toBeInTheDocument();
    });
  });

  it('shows revoke button only for active keys as org-admin', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByTestId('revoke-btn-key-001')).toBeInTheDocument();
      expect(screen.getByTestId('revoke-btn-key-002')).toBeInTheDocument();
      expect(screen.queryByTestId('revoke-btn-key-004')).not.toBeInTheDocument();
    });
  });

  it('hides Actions column for security-manager', async () => {
    setMockUser('security-manager');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('API Keys')).toBeInTheDocument();
      expect(screen.getByText('CI Pipeline')).toBeInTheDocument();
    });
    expect(screen.queryByText('Actions')).not.toBeInTheDocument();
    expect(screen.queryByTestId('revoke-btn-key-001')).not.toBeInTheDocument();
  });

  it('shows read-only notice for security-manager', async () => {
    setMockUser('security-manager');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText(/Read-only view/)).toBeInTheDocument();
    });
  });

  it('filters by owner', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('4 keys')).toBeInTheDocument();
    });

    const ownerFilter = screen.getByLabelText('Filter by owner');
    fireEvent.change(ownerFilter, { target: { value: 'sarah.kim@nk-sentinel.io' } });

    await waitFor(() => {
      expect(screen.getByText('1 key')).toBeInTheDocument();
    });
  });

  it('filters by status', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('4 keys')).toBeInTheDocument();
    });

    const statusFilter = screen.getByLabelText('Filter by status');
    fireEvent.change(statusFilter, { target: { value: 'revoked' } });

    await waitFor(() => {
      expect(screen.getByText('1 key')).toBeInTheDocument();
    });
  });

  it('has export CSV button', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByTestId('export-csv-btn')).toBeInTheDocument();
    });
  });

  it('denies access to developer', async () => {
    setMockUser('developer');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.queryByText('API Keys')).not.toBeInTheDocument();
    });
  });
});
