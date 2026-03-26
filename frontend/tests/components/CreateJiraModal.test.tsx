import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { CreateJiraModal } from '../../src/components/findings/CreateJiraModal';
import type { Finding } from '../../src/mocks/data/findings';

const MOCK_FINDING: Finding = {
  id: 'f-001',
  repoId: 'repo-1',
  severity: 'critical',
  file: 'SSLConfig.java',
  line: 45,
  title: 'Certificate validation disabled',
  algorithm: null,
  quantumStatus: 'vulnerable',
  pass: 1,
  ruleId: 'cbom-java-trust-all-certificates',
  confidence: 'high',
  assetType: 'Certificate',
  code: {
    startLine: 43,
    highlightLines: [45, 46],
    lines: [
      'TrustManager[] trustAll = new TrustManager[] {',
      '  new X509TrustManager() {',
      '    public void checkClientTrusted(X509Certificate[] certs, String authType) {}',
    ],
  },
  remediation: 'Use proper certificate validation.',
  status: 'open',
  firstSeen: '2026-03-20T10:00:00Z',
};

let lastPostedBody: Record<string, unknown> | null = null;

const server = setupServer(
  http.post('/api/v1/findings/:findingId/jira', async ({ request }) => {
    lastPostedBody = await request.json() as Record<string, unknown>;
    return HttpResponse.json({
      issueKey: 'SEC-F001',
      issueUrl: 'https://jira.example.com/browse/SEC-F001',
      summary: '[CipherRadar] CRITICAL: Certificate validation disabled',
    });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }));
afterEach(() => {
  server.resetHandlers();
  lastPostedBody = null;
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

describe('CreateJiraModal', () => {
  it('pre-fills form fields from finding data', () => {
    const onClose = () => {};
    renderWithProviders(
      <CreateJiraModal finding={MOCK_FINDING} onClose={onClose} />,
    );

    const summaryInput = screen.getByTestId('jira-summary') as HTMLInputElement;
    expect(summaryInput.value).toContain('Certificate validation disabled');

    const descriptionInput = screen.getByTestId('jira-description') as HTMLTextAreaElement;
    expect(descriptionInput.value).toContain('SSLConfig.java');

    const prioritySelect = screen.getByTestId('jira-priority') as HTMLSelectElement;
    expect(prioritySelect.value).toBe('Highest');
  });

  it('submits and shows created issue URL on success', async () => {
    const onClose = () => {};
    renderWithProviders(
      <CreateJiraModal finding={MOCK_FINDING} onClose={onClose} />,
    );

    const submitBtn = screen.getByTestId('jira-submit');
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(screen.getByTestId('jira-success-url')).toBeInTheDocument();
      expect(screen.getByText('SEC-F001')).toBeInTheDocument();
    });

    const link = screen.getByTestId('jira-success-url') as HTMLAnchorElement;
    expect(link.href).toBe('https://jira.example.com/browse/SEC-F001');
  });

  it('allows user to edit all fields before submitting', async () => {
    const onClose = () => {};
    renderWithProviders(
      <CreateJiraModal finding={MOCK_FINDING} onClose={onClose} />,
    );

    const summaryInput = screen.getByTestId('jira-summary') as HTMLInputElement;
    fireEvent.change(summaryInput, { target: { value: 'Custom summary' } });
    expect(summaryInput.value).toBe('Custom summary');

    const descriptionInput = screen.getByTestId('jira-description') as HTMLTextAreaElement;
    fireEvent.change(descriptionInput, { target: { value: 'Custom description' } });
    expect(descriptionInput.value).toBe('Custom description');

    const prioritySelect = screen.getByTestId('jira-priority') as HTMLSelectElement;
    fireEvent.change(prioritySelect, { target: { value: 'Low' } });
    expect(prioritySelect.value).toBe('Low');

    const submitBtn = screen.getByTestId('jira-submit');
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(lastPostedBody).not.toBeNull();
      expect(lastPostedBody!['summary']).toBe('Custom summary');
    });
  });

  it('calls onClose when close button is clicked', () => {
    let closed = false;
    renderWithProviders(
      <CreateJiraModal finding={MOCK_FINDING} onClose={() => { closed = true; }} />,
    );

    const closeBtn = screen.getByText('Cancel');
    fireEvent.click(closeBtn);
    expect(closed).toBe(true);
  });

  it('shows the modal overlay', () => {
    renderWithProviders(
      <CreateJiraModal finding={MOCK_FINDING} onClose={() => {}} />,
    );

    expect(screen.getByTestId('jira-modal')).toBeInTheDocument();
  });
});
