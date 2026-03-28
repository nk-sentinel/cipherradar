import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { GroupManagement } from '../../src/pages/admin/GroupManagement.tsx';
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

const MOCK_GROUPS = [
  {
    id: 'grp-001',
    name: 'Platform Engineering',
    description: 'Core platform services team',
    projectCount: 5,
    memberCount: 8,
    createdAt: '2026-01-15T10:00:00Z',
  },
  {
    id: 'grp-002',
    name: 'Security Team',
    description: 'Application security and compliance',
    projectCount: 3,
    memberCount: 4,
    createdAt: '2026-02-01T10:00:00Z',
  },
];

const MOCK_GROUP_DETAIL = {
  id: 'grp-001',
  name: 'Platform Engineering',
  description: 'Core platform services team',
  projectCount: 5,
  memberCount: 8,
  createdAt: '2026-01-15T10:00:00Z',
  members: [
    { email: 'alex.chen@nk-sentinel.io', name: 'Alex Chen', role: 'org-admin' },
    { email: 'sarah.kim@nk-sentinel.io', name: 'Sarah Kim', role: 'security-manager' },
  ],
  projects: [
    { id: 'proj-001', name: 'payment-service' },
    { id: 'proj-002', name: 'auth-api' },
  ],
};

const MOCK_ORG_SETTINGS = {
  id: 'org-001',
  name: 'nk-sentinel',
  plan: 'enterprise',
  defaultScanConfig: {
    autoScan: true,
    scanOnPr: true,
    policyFile: '',
    failOnSeverity: 'high',
  },
};

const server = setupServer(
  http.get('/api/v1/admin/groups', () => {
    return HttpResponse.json(MOCK_GROUPS);
  }),
  http.get('/api/v1/admin/groups/:groupId', () => {
    return HttpResponse.json(MOCK_GROUP_DETAIL);
  }),
  http.post('/api/v1/admin/groups', async ({ request }) => {
    const body = await request.json() as { name: string; description: string };
    return HttpResponse.json({
      id: 'grp-new',
      name: body.name,
      description: body.description,
      projectCount: 0,
      memberCount: 0,
      createdAt: new Date().toISOString(),
    }, { status: 201 });
  }),
  http.get('/api/v1/admin/settings', () => {
    return HttpResponse.json(MOCK_ORG_SETTINGS);
  }),
  http.get('/api/v1/user/orgs', () => {
    return HttpResponse.json(MOCK_ORGS);
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
  const groupsRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/admin/groups',
    component: GroupManagement,
  });
  const dashRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/',
    component: () => <div>Dashboard</div>,
  });

  const routeTree = rootRoute.addChildren([groupsRoute, dashRoute]);

  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ['/admin/groups'] }),
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

describe('GroupManagement page', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* jsdom may not support */ }
    try { localStorage.clear(); } catch { /* jsdom may not support */ }
  });

  it('renders page title for org-admin', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Groups')).toBeInTheDocument();
    });
  });

  it('renders table headers', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Group Name')).toBeInTheDocument();
      expect(screen.getByText('Project Count')).toBeInTheDocument();
      expect(screen.getByText('Member Count')).toBeInTheDocument();
      expect(screen.getByText('Created')).toBeInTheDocument();
    });
  });

  it('renders group rows', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Platform Engineering')).toBeInTheDocument();
      expect(screen.getByText('Security Team')).toBeInTheDocument();
    });
  });

  it('shows group count', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('2 groups')).toBeInTheDocument();
    });
  });

  it('shows Add Group button for org-admin', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByTestId('add-group-btn')).toBeInTheDocument();
    });
  });

  it('hides Add Group button for security-manager', async () => {
    setMockUser('security-manager');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Groups')).toBeInTheDocument();
    });
    expect(screen.queryByTestId('add-group-btn')).not.toBeInTheDocument();
  });

  it('opens add group modal', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByTestId('add-group-btn')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('add-group-btn'));

    await waitFor(() => {
      expect(screen.getByTestId('group-name-input')).toBeInTheDocument();
      expect(screen.getByTestId('group-description-input')).toBeInTheDocument();
      expect(screen.getByTestId('create-group-btn')).toBeInTheDocument();
    });
  });

  it('opens detail drawer on row click', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Platform Engineering')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('group-row-grp-001'));

    await waitFor(() => {
      expect(screen.getByTestId('group-detail-backdrop')).toBeInTheDocument();
      expect(screen.getByText('Alex Chen')).toBeInTheDocument();
      expect(screen.getByText('payment-service')).toBeInTheDocument();
    });
  });

  it('denies access to developer', async () => {
    setMockUser('developer');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.queryByText('Groups')).not.toBeInTheDocument();
    });
  });
});
