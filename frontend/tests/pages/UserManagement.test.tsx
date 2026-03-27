import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { UserManagement } from '../../src/pages/admin/UserManagement.tsx';
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

const MOCK_USERS_PAGE1 = {
  items: [
    {
      id: 'u-001',
      name: 'Alex Chen',
      email: 'alex.chen@nk-sentinel.io',
      role: 'org-admin',
      authSource: 'local',
      lastActive: '2 hours ago',
      status: 'active',
      groups: [{ id: 'g-001', name: 'Platform Team' }],
      apiKeyCount: 2,
      createdAt: '2026-01-15',
    },
    {
      id: 'u-002',
      name: 'Sarah Kim',
      email: 'sarah.kim@nk-sentinel.io',
      role: 'security-manager',
      authSource: 'local',
      lastActive: '5 minutes ago',
      status: 'active',
      groups: [],
      apiKeyCount: 0,
      createdAt: '2026-02-01',
    },
    {
      id: 'u-003',
      name: 'James Liu',
      email: 'james.liu@nk-sentinel.io',
      role: 'security-engineer',
      authSource: 'okta',
      lastActive: '45 days ago',
      status: 'active',
      groups: [],
      apiKeyCount: 1,
      createdAt: '2026-02-10',
    },
    {
      id: 'u-004',
      name: 'Old User',
      email: 'old@nk-sentinel.io',
      role: 'developer',
      authSource: 'local',
      lastActive: '120 days ago',
      status: 'disabled',
      groups: [],
      apiKeyCount: 0,
      createdAt: '2025-06-01',
    },
    {
      id: 'u-005',
      name: 'Tom Nguyen',
      email: 'tom.nguyen@nk-sentinel.io',
      role: 'guest',
      authSource: 'local',
      lastActive: 'Never',
      status: 'invited',
      groups: [],
      apiKeyCount: 0,
      createdAt: '2026-03-20',
    },
  ],
  total: 12,
  page: 1,
  perPage: 25,
};

const server = setupServer(
  http.get('/api/v1/admin/users', ({ request }) => {
    const url = new URL(request.url);
    const search = url.searchParams.get('search') || '';
    let items = MOCK_USERS_PAGE1.items;
    if (search) {
      items = items.filter(
        (u) =>
          u.name.toLowerCase().includes(search.toLowerCase()) ||
          u.email.toLowerCase().includes(search.toLowerCase()),
      );
    }
    return HttpResponse.json({
      items,
      total: items.length,
      page: Number(url.searchParams.get('page') || '1'),
      perPage: Number(url.searchParams.get('perPage') || '25'),
    });
  }),
  http.get('/api/v1/user/orgs', () => {
    return HttpResponse.json(MOCK_ORGS);
  }),
  http.patch('/api/v1/admin/users/:userId/role', async () => {
    return HttpResponse.json({ success: true });
  }),
  http.post('/api/v1/admin/users/:userId/disable', () => {
    return HttpResponse.json({ success: true });
  }),
  http.post('/api/v1/admin/users/:userId/enable', () => {
    return HttpResponse.json({ success: true });
  }),
  http.delete('/api/v1/admin/users/:userId', () => {
    return new HttpResponse(null, { status: 204 });
  }),
  http.post('/api/v1/admin/users/invite', async () => {
    return HttpResponse.json({ success: true });
  }),
  http.post('/api/v1/admin/users', async () => {
    return HttpResponse.json({ success: true, id: 'u-new' });
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
  const usersRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/admin/users',
    component: UserManagement,
  });
  const dashRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/',
    component: () => <div>Dashboard</div>,
  });

  const routeTree = rootRoute.addChildren([usersRoute, dashRoute]);

  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ['/admin/users'] }),
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

describe('UserManagement — overhauled', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* ignore */ }
    try { localStorage.clear(); } catch { /* ignore */ }
  });

  it('renders page title and add user button', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('User Management')).toBeInTheDocument();
      expect(screen.getByTestId('add-user-btn')).toBeInTheDocument();
    });
  });

  it('renders table with server-side pagination', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Users (12)')).toBeInTheDocument();
      expect(screen.getByText('Alex Chen')).toBeInTheDocument();
    });
    // Pagination should exist
    expect(screen.getByText(/Showing/)).toBeInTheDocument();
  });

  it('renders search input', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByTestId('user-search')).toBeInTheDocument();
    });
  });

  it('shows inline role dropdown for org-admin', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByTestId('role-select-u-001')).toBeInTheDocument();
    });
  });

  it('shows role badge instead of dropdown for security-manager', async () => {
    setMockUser('security-manager');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Alex Chen')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('role-select-u-001')).not.toBeInTheDocument();
  });

  it('shows disable button for active users', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByTestId('disable-btn-u-001')).toBeInTheDocument();
    });
  });

  it('shows enable and delete buttons for disabled users', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByTestId('enable-btn-u-004')).toBeInTheDocument();
      expect(screen.getByTestId('delete-btn-u-004')).toBeInTheDocument();
    });
  });

  it('does not show delete button for active users', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Alex Chen')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('delete-btn-u-001')).not.toBeInTheDocument();
  });

  it('shows stale indicator for users inactive >30 days', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      // James Liu is 45 days ago (orange)
      expect(screen.getByTestId('stale-indicator-u-003')).toBeInTheDocument();
    });
  });

  it('shows stale indicator (red) for users inactive >90 days', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      // Old User is 120 days ago (red)
      expect(screen.getByTestId('stale-indicator-u-004')).toBeInTheDocument();
    });
  });

  it('shows stale indicator (red) for Never active', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByTestId('stale-indicator-u-005')).toBeInTheDocument();
    });
  });

  it('opens detail drawer on row click', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByTestId('user-row-u-001')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('user-row-u-001'));

    await waitFor(() => {
      expect(screen.getByTestId('user-detail-drawer')).toBeInTheDocument();
      expect(screen.getByText('User Details')).toBeInTheDocument();
    });
  });

  it('shows create modal when add user button is clicked', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByTestId('add-user-btn')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('add-user-btn'));

    await waitFor(() => {
      expect(screen.getByTestId('user-create-modal')).toBeInTheDocument();
    });
  });
});
