import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { JiraConfigSection } from '../../src/components/settings/JiraConfigSection';

const MOCK_JIRA_CONFIG = {
  id: 'jc-001',
  jiraProjectKey: 'SEC',
  defaultIssueType: 'Bug',
  priorityMapping: { critical: 'Highest', high: 'High', medium: 'Medium', low: 'Low' },
  customFields: {},
  defaultAssignee: 'admin@example.com',
  labels: ['crypto', 'cipherradar'],
  scope: 'group' as const,
};

let lastSavedBody: Record<string, unknown> | null = null;

const server = setupServer(
  http.get('/api/v1/groups/:groupId/jira-config', () => {
    return HttpResponse.json(MOCK_JIRA_CONFIG);
  }),
  http.put('/api/v1/groups/:groupId/jira-config', async ({ request }) => {
    lastSavedBody = await request.json() as Record<string, unknown>;
    return HttpResponse.json({
      id: 'jc-001',
      ...(lastSavedBody as object),
      scope: 'group',
    });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }));
afterEach(() => {
  server.resetHandlers();
  lastSavedBody = null;
});
afterAll(() => server.close());

function renderWithProviders(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>,
  );
}

describe('JiraConfigSection', () => {
  it('renders the form with existing config data', async () => {
    renderWithProviders(
      <JiraConfigSection scopeType="group" scopeId="group-1" />,
    );

    await waitFor(() => {
      const projectKeyInput = screen.getByTestId('jira-project-key') as HTMLInputElement;
      expect(projectKeyInput.value).toBe('SEC');
    });

    const issueTypeSelect = screen.getByTestId('jira-issue-type') as HTMLSelectElement;
    expect(issueTypeSelect.value).toBe('Bug');

    const assigneeInput = screen.getByTestId('jira-assignee') as HTMLInputElement;
    expect(assigneeInput.value).toBe('admin@example.com');
  });

  it('saves config on submit', async () => {
    renderWithProviders(
      <JiraConfigSection scopeType="group" scopeId="group-1" />,
    );

    await waitFor(() => {
      expect(screen.getByTestId('jira-project-key')).toBeInTheDocument();
    });

    // Change project key
    const projectKeyInput = screen.getByTestId('jira-project-key') as HTMLInputElement;
    fireEvent.change(projectKeyInput, { target: { value: 'NEWSEC' } });

    const saveBtn = screen.getByTestId('jira-config-save');
    fireEvent.click(saveBtn);

    await waitFor(() => {
      expect(lastSavedBody).not.toBeNull();
      expect(lastSavedBody!['jiraProjectKey']).toBe('NEWSEC');
    });
  });

  it('renders form fields for configuration', async () => {
    renderWithProviders(
      <JiraConfigSection scopeType="group" scopeId="group-1" />,
    );

    await waitFor(() => {
      expect(screen.getByTestId('jira-project-key')).toBeInTheDocument();
    });

    expect(screen.getByTestId('jira-issue-type')).toBeInTheDocument();
    expect(screen.getByTestId('jira-assignee')).toBeInTheDocument();
    expect(screen.getByTestId('jira-labels')).toBeInTheDocument();
    expect(screen.getByText('Priority Mapping')).toBeInTheDocument();
    expect(screen.getByTestId('jira-config-save')).toBeInTheDocument();
  });

  it('shows empty state when no config exists', async () => {
    server.use(
      http.get('/api/v1/groups/:groupId/jira-config', () => {
        return new HttpResponse(null, { status: 404 });
      }),
    );

    renderWithProviders(
      <JiraConfigSection scopeType="group" scopeId="group-1" />,
    );

    await waitFor(() => {
      expect(screen.getByTestId('jira-config-empty')).toBeInTheDocument();
      expect(screen.getByText(/not configured/i)).toBeInTheDocument();
    });
  });

  it('renders priority mapping rows', async () => {
    renderWithProviders(
      <JiraConfigSection scopeType="group" scopeId="group-1" />,
    );

    await waitFor(() => {
      expect(screen.getByTestId('jira-project-key')).toBeInTheDocument();
    });

    expect(screen.getByTestId('priority-critical')).toBeInTheDocument();
    expect(screen.getByTestId('priority-high')).toBeInTheDocument();
    expect(screen.getByTestId('priority-medium')).toBeInTheDocument();
    expect(screen.getByTestId('priority-low')).toBeInTheDocument();
  });
});
