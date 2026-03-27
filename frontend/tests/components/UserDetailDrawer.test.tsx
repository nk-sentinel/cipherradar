import { describe, it, expect, vi, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { UserDetailDrawer } from '../../src/components/admin/UserDetailDrawer.tsx';
import type { ManagedUser } from '../../src/api/hooks/useUserManagement.ts';

const server = setupServer(
  http.post('/api/v1/admin/users/:userId/disable', () => {
    return HttpResponse.json({ success: true });
  }),
  http.post('/api/v1/admin/users/:userId/enable', () => {
    return HttpResponse.json({ success: true });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const MOCK_ACTIVE_LOCAL_USER: ManagedUser = {
  id: 'u-001',
  name: 'Alex Chen',
  email: 'alex.chen@nk-sentinel.io',
  role: 'org-admin',
  authSource: 'local',
  lastActive: '2 hours ago',
  status: 'active',
  groups: [{ id: 'g-001', name: 'Platform Team' }],
  apiKeyCount: 3,
  createdAt: '2026-01-15',
};

const MOCK_DISABLED_SSO_USER: ManagedUser = {
  id: 'u-003',
  name: 'James Liu',
  email: 'james.liu@nk-sentinel.io',
  role: 'security-engineer',
  authSource: 'okta',
  lastActive: '45 days ago',
  status: 'disabled',
  groups: [],
  apiKeyCount: 0,
  createdAt: '2026-02-10',
};

function renderWithProviders(user: ManagedUser, onClose = vi.fn()) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <UserDetailDrawer user={user} onClose={onClose} />
    </QueryClientProvider>,
  );
}

describe('UserDetailDrawer', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* ignore */ }
  });

  it('renders drawer with user details', () => {
    renderWithProviders(MOCK_ACTIVE_LOCAL_USER);
    expect(screen.getByTestId('user-detail-drawer')).toBeInTheDocument();
    expect(screen.getByText('Alex Chen')).toBeInTheDocument();
    expect(screen.getByText('alex.chen@nk-sentinel.io')).toBeInTheDocument();
    expect(screen.getByText('Org Admin')).toBeInTheDocument();
    expect(screen.getByText('local')).toBeInTheDocument();
    expect(screen.getByText('2 hours ago')).toBeInTheDocument();
    expect(screen.getByText('2026-01-15')).toBeInTheDocument();
  });

  it('shows group memberships', () => {
    renderWithProviders(MOCK_ACTIVE_LOCAL_USER);
    expect(screen.getByText('Platform Team')).toBeInTheDocument();
  });

  it('shows "None" for users with no groups', () => {
    renderWithProviders(MOCK_DISABLED_SSO_USER);
    expect(screen.getByText('None')).toBeInTheDocument();
  });

  it('shows API key count', () => {
    renderWithProviders(MOCK_ACTIVE_LOCAL_USER);
    expect(screen.getByText('3')).toBeInTheDocument();
  });

  it('shows disable button for active users', () => {
    renderWithProviders(MOCK_ACTIVE_LOCAL_USER);
    expect(screen.getByTestId('drawer-disable-btn')).toBeInTheDocument();
    expect(screen.queryByTestId('drawer-enable-btn')).not.toBeInTheDocument();
  });

  it('shows enable button for disabled users', () => {
    renderWithProviders(MOCK_DISABLED_SSO_USER);
    expect(screen.getByTestId('drawer-enable-btn')).toBeInTheDocument();
    expect(screen.queryByTestId('drawer-disable-btn')).not.toBeInTheDocument();
  });

  it('shows reset password button for local auth source', () => {
    renderWithProviders(MOCK_ACTIVE_LOCAL_USER);
    expect(screen.getByTestId('drawer-reset-password-btn')).toBeInTheDocument();
  });

  it('hides reset password button for SSO auth source', () => {
    renderWithProviders(MOCK_DISABLED_SSO_USER);
    expect(screen.queryByTestId('drawer-reset-password-btn')).not.toBeInTheDocument();
  });

  it('close button calls onClose', () => {
    const onClose = vi.fn();
    renderWithProviders(MOCK_ACTIVE_LOCAL_USER, onClose);
    fireEvent.click(screen.getByTestId('drawer-close'));
    expect(onClose).toHaveBeenCalled();
  });

  it('renders user initials avatar', () => {
    renderWithProviders(MOCK_ACTIVE_LOCAL_USER);
    expect(screen.getByText('AC')).toBeInTheDocument();
  });
});
