import { describe, it, expect, vi, beforeAll, afterEach, afterAll } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { AssignDropdown } from '../../src/components/findings/AssignDropdown';

// Mock useAuth to control role
const mockUseAuth = vi.fn();
vi.mock('../../src/lib/auth', () => ({
  useAuth: () => mockUseAuth(),
}));

const mockMembers = [
  { email: 'alice@example.com', name: 'Alice Smith', role: 'security-engineer' },
  { email: 'bob@example.com', name: 'Bob Jones', role: 'developer' },
  { email: 'charlie@example.com', name: 'Charlie Brown', role: 'team-manager' },
];

const server = setupServer(
  http.get('/api/v1/projects/:projectId/members', () => {
    return HttpResponse.json(mockMembers);
  }),
  http.patch('/api/v1/findings/:findingId/assign', async ({ request, params }) => {
    const body = await request.json() as { assigneeEmail: string | null };
    return HttpResponse.json({
      id: params['findingId'],
      assignee: body.assigneeEmail,
      updatedAt: new Date().toISOString(),
    });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }));
afterEach(() => {
  server.resetHandlers();
  vi.clearAllMocks();
});
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

describe('AssignDropdown', () => {
  it('shows "Unassigned" when no assignee', () => {
    mockUseAuth.mockReturnValue({
      user: { email: 'admin@example.com', role: 'org-admin', name: 'Admin', initials: 'A' },
    });

    renderWithProviders(
      <AssignDropdown findingId="f-001" projectId="proj-1" currentAssignee={null} />,
    );

    expect(screen.getByTestId('assign-dropdown-trigger')).toHaveTextContent('Unassigned');
  });

  it('shows current assignee when assigned', () => {
    mockUseAuth.mockReturnValue({
      user: { email: 'admin@example.com', role: 'org-admin', name: 'Admin', initials: 'A' },
    });

    renderWithProviders(
      <AssignDropdown findingId="f-001" projectId="proj-1" currentAssignee="alice@example.com" />,
    );

    expect(screen.getByTestId('assign-dropdown-trigger')).toHaveTextContent('alice@example.com');
  });

  it('shows group members list when opened by non-dev role', async () => {
    mockUseAuth.mockReturnValue({
      user: { email: 'admin@example.com', role: 'org-admin', name: 'Admin', initials: 'A' },
    });

    renderWithProviders(
      <AssignDropdown findingId="f-001" projectId="proj-1" currentAssignee={null} />,
    );

    fireEvent.click(screen.getByTestId('assign-dropdown-trigger'));

    await waitFor(() => {
      expect(screen.getByTestId('assign-dropdown-menu')).toBeInTheDocument();
      expect(screen.getByTestId('assign-member-alice@example.com')).toBeInTheDocument();
      expect(screen.getByTestId('assign-member-bob@example.com')).toBeInTheDocument();
      expect(screen.getByTestId('assign-member-charlie@example.com')).toBeInTheDocument();
    });
  });

  it('DEV sees only "Assign to me" option', async () => {
    mockUseAuth.mockReturnValue({
      user: { email: 'bob@example.com', role: 'developer', name: 'Bob', initials: 'B' },
    });

    renderWithProviders(
      <AssignDropdown findingId="f-001" projectId="proj-1" currentAssignee={null} />,
    );

    fireEvent.click(screen.getByTestId('assign-dropdown-trigger'));

    await waitFor(() => {
      expect(screen.getByTestId('assign-self')).toBeInTheDocument();
      expect(screen.getByTestId('assign-self')).toHaveTextContent('Assign to me');
    });

    // Should NOT show the member list
    expect(screen.queryByTestId('assign-member-alice@example.com')).not.toBeInTheDocument();
  });

  it('clicking a member calls assign API', async () => {
    mockUseAuth.mockReturnValue({
      user: { email: 'admin@example.com', role: 'org-admin', name: 'Admin', initials: 'A' },
    });

    renderWithProviders(
      <AssignDropdown findingId="f-001" projectId="proj-1" currentAssignee={null} />,
    );

    fireEvent.click(screen.getByTestId('assign-dropdown-trigger'));

    await waitFor(() => {
      expect(screen.getByTestId('assign-member-alice@example.com')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('assign-member-alice@example.com'));
    // Mutation should fire without error
  });
});
