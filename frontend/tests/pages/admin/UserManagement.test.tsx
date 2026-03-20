import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { MOCK_ORG_USERS, MOCK_ORGS } from '../../../src/mocks/data/admin.ts';
import { UserManagement } from '../../../src/pages/admin/UserManagement.tsx';
import { AuthProvider } from '../../../src/lib/auth.tsx';
import { OrgProvider } from '../../../src/lib/org-context.tsx';
import {
  createRouter,
  createRootRoute,
  createRoute,
  RouterProvider,
  createMemoryHistory,
} from '@tanstack/react-router';
import { applyTheme, type Theme } from '../../../src/lib/themes.ts';

const server = setupServer(
  http.get('/api/v1/admin/users', () => {
    return HttpResponse.json(MOCK_ORG_USERS);
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
    name: 'Test User',
    email: 'test@example.com',
    role,
    initials: 'TU',
  };
  sessionStorage.setItem('cipherradar-token', 'mock-token');
  sessionStorage.setItem('cipherradar-user', JSON.stringify(user));
}

function renderWithProviders() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
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

describe('UserManagement page', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* jsdom may not support */ }
    try { localStorage.clear(); } catch { /* jsdom may not support */ }
  });

  it('renders the page title for org-admin', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('User Management')).toBeInTheDocument();
    });
  });

  it('renders invite user button', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('+ Invite User')).toBeInTheDocument();
    });
  });

  it('renders user table headers', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Name')).toBeInTheDocument();
      expect(screen.getByText('Email')).toBeInTheDocument();
      expect(screen.getByText('Role')).toBeInTheDocument();
      expect(screen.getByText('Last Active')).toBeInTheDocument();
      expect(screen.getByText('Status')).toBeInTheDocument();
    });
  });

  it('renders all mock users', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Alex Chen')).toBeInTheDocument();
      expect(screen.getByText('Sarah Kim')).toBeInTheDocument();
      expect(screen.getByText('James Liu')).toBeInTheDocument();
      expect(screen.getByText('Maria Garcia')).toBeInTheDocument();
      expect(screen.getByText('David Park')).toBeInTheDocument();
      expect(screen.getByText('Emily Zhao')).toBeInTheDocument();
      expect(screen.getByText('Tom Nguyen')).toBeInTheDocument();
    });
  });

  it('renders user count', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Users (7)')).toBeInTheDocument();
    });
  });

  it('renders role badges', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Org Admin')).toBeInTheDocument();
      expect(screen.getByText('Security Manager')).toBeInTheDocument();
      expect(screen.getByText('Security Engineer')).toBeInTheDocument();
      expect(screen.getByText('Team Manager')).toBeInTheDocument();
      expect(screen.getByText('Compliance Auditor')).toBeInTheDocument();
      expect(screen.getByText('Developer')).toBeInTheDocument();
    });
  });

  it('renders user emails', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('alex.chen@nk-sentinel.io')).toBeInTheDocument();
      expect(screen.getByText('sarah.kim@nk-sentinel.io')).toBeInTheDocument();
    });
  });

  it('shows invite form when clicking invite button', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('+ Invite User')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('+ Invite User'));

    await waitFor(() => {
      expect(screen.getByText('Invite New User')).toBeInTheDocument();
      expect(screen.getByText('Email Address')).toBeInTheDocument();
    });
  });

  it('redirects unauthorized roles', async () => {
    setMockUser('developer');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.queryByText('User Management')).not.toBeInTheDocument();
    });
  });

  it('renders for security-manager', async () => {
    setMockUser('security-manager');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('User Management')).toBeInTheDocument();
    });
  });
});

describe('UserManagement page - themes', () => {
  const themes: Theme[] = ['radar', 'crystal', 'sentinel'];

  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* jsdom may not support */ }
    try { localStorage.clear(); } catch { /* jsdom may not support */ }
  });

  themes.forEach((theme) => {
    it(`renders correctly with ${theme} theme`, async () => {
      applyTheme(theme);
      setMockUser('org-admin');
      renderWithProviders();
      await waitFor(() => {
        expect(screen.getByText('User Management')).toBeInTheDocument();
      });
      expect(document.body.className).toBe(`theme-${theme}`);
    });
  });
});
