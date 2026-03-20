import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { MOCK_ORG_SETTINGS, MOCK_ORGS } from '../../../src/mocks/data/admin.ts';
import { OrgSettings } from '../../../src/pages/admin/OrgSettings.tsx';
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
  const settingsRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/admin/settings',
    component: OrgSettings,
  });
  const dashRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/',
    component: () => <div>Dashboard</div>,
  });

  const routeTree = rootRoute.addChildren([settingsRoute, dashRoute]);

  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ['/admin/settings'] }),
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

describe('OrgSettings page', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* jsdom may not support */ }
    try { localStorage.clear(); } catch { /* jsdom may not support */ }
  });

  it('renders the page title for org-admin', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Organization Settings')).toBeInTheDocument();
    });
  });

  it('renders the page title for security-manager', async () => {
    setMockUser('security-manager');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Organization Settings')).toBeInTheDocument();
    });
  });

  it('renders org name input', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Organization Name')).toBeInTheDocument();
    });
  });

  it('renders plan field', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Plan')).toBeInTheDocument();
    });
  });

  it('renders default scan configuration section', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Default Scan Configuration')).toBeInTheDocument();
    });
  });

  it('renders auto-scan checkbox', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(
        screen.getByText('Enable automatic scanning on repository import'),
      ).toBeInTheDocument();
    });
  });

  it('renders scan-on-PR checkbox', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Scan on pull request merge')).toBeInTheDocument();
    });
  });

  it('renders fail on severity selector', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Fail on Severity')).toBeInTheDocument();
    });
  });

  it('renders save button', async () => {
    setMockUser('org-admin');
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Save Changes')).toBeInTheDocument();
    });
  });

  it('redirects unauthorized roles', async () => {
    setMockUser('developer');
    renderWithProviders();
    await waitFor(() => {
      // Should not render the org settings page
      expect(screen.queryByText('Organization Settings')).not.toBeInTheDocument();
    });
  });
});

describe('OrgSettings page - themes', () => {
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
        expect(screen.getByText('Organization Settings')).toBeInTheDocument();
      });
      expect(document.body.className).toBe(`theme-${theme}`);
    });
  });
});
