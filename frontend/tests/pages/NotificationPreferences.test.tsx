import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { MOCK_NOTIFICATION_PREFERENCES } from '../../src/mocks/data/notifications.ts';
import { NotificationPreferences } from '../../src/pages/NotificationPreferences.tsx';
import {
  createRouter,
  createRootRoute,
  createRoute,
  RouterProvider,
  createMemoryHistory,
} from '@tanstack/react-router';

const server = setupServer(
  http.get('/api/v1/notifications/preferences', () => {
    return HttpResponse.json(MOCK_NOTIFICATION_PREFERENCES);
  }),
  http.put('/api/v1/notifications/preferences', async ({ request }) => {
    const body = await request.json();
    return HttpResponse.json(body);
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderWithProviders() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });

  const rootRoute = createRootRoute();
  const prefsRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/notifications/preferences',
    component: NotificationPreferences,
  });

  const routeTree = rootRoute.addChildren([prefsRoute]);

  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ['/notifications/preferences'] }),
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}

describe('NotificationPreferences page', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* jsdom may not support */ }
  });

  it('renders the page title', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Notification Preferences')).toBeInTheDocument();
    });
  });

  it('renders save button', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Save Changes')).toBeInTheDocument();
    });
  });

  it('renders all trigger preferences', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('New Critical Finding')).toBeInTheDocument();
      expect(screen.getByText('Compliance Score Drop')).toBeInTheDocument();
      expect(screen.getByText('Scan Complete')).toBeInTheDocument();
      expect(screen.getByText('Suppression Request')).toBeInTheDocument();
      expect(screen.getByText('Certificate Expiry Warning')).toBeInTheDocument();
      expect(screen.getByText('Quantum Risk Score Change')).toBeInTheDocument();
    });
  });

  it('renders trigger descriptions', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(
        screen.getByText('When a scan detects a new critical-severity finding'),
      ).toBeInTheDocument();
      expect(
        screen.getByText('When a repository compliance score drops by 5% or more'),
      ).toBeInTheDocument();
    });
  });

  it('renders toggle switches for in-app and email', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('New Critical Finding')).toBeInTheDocument();
      // Each trigger has 2 toggles: in-app and email
      const switches = screen.getAllByRole('switch');
      expect(switches.length).toBe(12); // 6 triggers x 2 channels
    });
  });

  it('renders Jira integration status', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Jira Integration')).toBeInTheDocument();
      expect(screen.getByText('Connected')).toBeInTheDocument();
      expect(screen.getByText('https://nk-sentinel.atlassian.net')).toBeInTheDocument();
    });
  });

  it('renders Teams webhook configuration', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Microsoft Teams Webhook')).toBeInTheDocument();
      const input = screen.getByLabelText('Webhook URL') as HTMLInputElement;
      expect(input.value).toBe('https://outlook.office.com/webhook/abc123');
    });
  });

  it('toggles a preference switch', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('New Critical Finding')).toBeInTheDocument();
    });

    // Find the in-app toggle for "New Critical Finding"
    const toggle = screen.getByLabelText('New Critical Finding in-app');
    expect(toggle.getAttribute('aria-checked')).toBe('true');

    fireEvent.click(toggle);

    await waitFor(() => {
      expect(toggle.getAttribute('aria-checked')).toBe('false');
    });
  });

  it('renders Alert Triggers section header', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Alert Triggers')).toBeInTheDocument();
    });
  });

  it('renders table headers for triggers', async () => {
    renderWithProviders();
    await waitFor(() => {
      expect(screen.getByText('Trigger')).toBeInTheDocument();
      expect(screen.getByText('Description')).toBeInTheDocument();
      expect(screen.getByText('In-App')).toBeInTheDocument();
      expect(screen.getByText('Email')).toBeInTheDocument();
    });
  });
});
