import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { MOCK_AUDIT_LOG, MOCK_ORGS } from '../../../src/mocks/data/admin.ts';
import { AuditLog } from '../../../src/pages/admin/AuditLog.tsx';
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
  http.get('/api/v1/admin/audit-log', () => {
    return HttpResponse.json(MOCK_AUDIT_LOG);
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
  const auditRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/admin/audit-log',
    component: AuditLog,
  });
  const dashRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/',
    component: () => <div>Dashboard</div>,
  });

  const routeTree = rootRoute.addChildren([auditRoute, dashRoute]);

  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ['/admin/audit-log'] }),
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

describe('AuditLog page', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* jsdom may not support */ }
    try { localStorage.clear(); } catch { /* jsdom may not support */ }
  });

  it('renders the page title for org-admin', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Audit Log')).toBeInTheDocument();
    });
  });

  it('renders table headers', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Timestamp')).toBeInTheDocument();
      expect(screen.getByText('User')).toBeInTheDocument();
      expect(screen.getByText('Action')).toBeInTheDocument();
      expect(screen.getByText('Resource')).toBeInTheDocument();
      expect(screen.getByText('Detail')).toBeInTheDocument();
    });
  });

  it('renders audit log entries', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('payment-service')).toBeInTheDocument();
      expect(screen.getByText('alex.chen@nk-sentinel.io')).toBeInTheDocument();
    });
  });

  it('renders action badges', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Scan Completed')).toBeInTheDocument();
      expect(screen.getByText('Policy Updated')).toBeInTheDocument();
      expect(screen.getByText('User Invited')).toBeInTheDocument();
    });
  });

  it('renders entry count', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('10 entries')).toBeInTheDocument();
    });
  });

  it('renders category filter', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByLabelText('Filter by action category')).toBeInTheDocument();
    });
  });

  it('filters entries by category', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('10 entries')).toBeInTheDocument();
    });

    const filter = screen.getByLabelText('Filter by action category');
    fireEvent.change(filter, { target: { value: 'scan' } });

    await waitFor(() => {
      expect(screen.getByText('2 entries')).toBeInTheDocument();
    });
  });

  it('renders audit detail text', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(
        screen.getByText('Scan #45 completed with 3 critical findings'),
      ).toBeInTheDocument();
    });
  });

  it('redirects unauthorized roles', async () => {
    setMockUser('developer');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.queryByText('Audit Log')).not.toBeInTheDocument();
    });
  });

  it('renders for security-manager', async () => {
    setMockUser('security-manager');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Audit Log')).toBeInTheDocument();
    });
  });
});

describe('AuditLog page - themes', () => {
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
        expect(screen.getByText('Audit Log')).toBeInTheDocument();
      });
      expect(document.body.className).toBe(`theme-${theme}`);
    });
  });
});
