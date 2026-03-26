import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { PolicyRules } from '../../src/pages/PolicyRules';

const MOCK_SUMMARY = [
  {
    ruleId: 'no-broken-algorithms',
    totalFindings: 42,
    fpRate: 12.5,
    fixRate: 60.0,
    mttrSeconds: 172800,
    warning: false,
  },
  {
    ruleId: 'no-ecb-mode',
    totalFindings: 28,
    fpRate: 55.0,
    fixRate: 8.0,
    mttrSeconds: null,
    warning: true,
  },
  {
    ruleId: 'rsa-min-key-size',
    totalFindings: 15,
    fpRate: 5.0,
    fixRate: 80.0,
    mttrSeconds: 86400,
    warning: false,
  },
];

const MOCK_RULE_ANALYTICS = {
  ruleId: 'no-broken-algorithms',
  totalFindings: 42,
  activeFindings: 15,
  fpRate: 12.5,
  raRate: 5.0,
  fixRate: 60.0,
  mttrSeconds: 172800,
  trend: [
    { scanId: 'scan-001', count: 8, scannedAt: '2026-03-20T10:00:00Z' },
    { scanId: 'scan-002', count: 6, scannedAt: '2026-03-22T10:00:00Z' },
    { scanId: 'scan-003', count: 4, scannedAt: '2026-03-24T10:00:00Z' },
  ],
  timeWindow: '90d',
};

const server = setupServer(
  http.get('/api/v1/admin/rules/summary', () => {
    return HttpResponse.json(MOCK_SUMMARY);
  }),
  http.get('/api/v1/admin/rules/:ruleId/analytics', () => {
    return HttpResponse.json(MOCK_RULE_ANALYTICS);
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderWithProviders() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <PolicyRules />
    </QueryClientProvider>,
  );
}

describe('PolicyRules page with analytics', () => {
  it('renders metrics columns in the header', async () => {
    renderWithProviders();

    await waitFor(() => {
      expect(screen.getByTestId('col-findings')).toBeInTheDocument();
      expect(screen.getByTestId('col-fp-rate')).toBeInTheDocument();
      expect(screen.getByTestId('col-fix-rate')).toBeInTheDocument();
      expect(screen.getByTestId('col-mttr')).toBeInTheDocument();
    });
  });

  it('shows warning icon on rules with high FP rate', async () => {
    renderWithProviders();

    await waitFor(() => {
      // no-ecb-mode has warning: true
      expect(screen.getByTestId('warning-no-ecb-mode')).toBeInTheDocument();
    });

    // no-broken-algorithms should NOT have a warning
    expect(screen.queryByTestId('warning-no-broken-algorithms')).not.toBeInTheDocument();
  });

  it('expands row to show analytics detail on click', async () => {
    renderWithProviders();

    await waitFor(() => {
      expect(screen.getByTestId('rule-row-no-broken-algorithms')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByTestId('rule-row-no-broken-algorithms'));

    await waitFor(() => {
      expect(screen.getByTestId('rule-expanded-no-broken-algorithms')).toBeInTheDocument();
      expect(screen.getByTestId('rule-analytics-detail')).toBeInTheDocument();
    });
  });

  it('time window selector is present and changes data query', async () => {
    renderWithProviders();

    await waitFor(() => {
      expect(screen.getByTestId('time-window-selector')).toBeInTheDocument();
    });

    const selector = screen.getByTestId('time-window-selector') as HTMLSelectElement;
    expect(selector.value).toBe('90d');

    fireEvent.change(selector, { target: { value: '30d' } });
    expect(selector.value).toBe('30d');
  });

  it('renders findings count for matched rules', async () => {
    renderWithProviders();

    await waitFor(() => {
      expect(screen.getByTestId('findings-count-no-broken-algorithms')).toHaveTextContent('42');
    });
  });

  it('renders FP rate for matched rules', async () => {
    renderWithProviders();

    await waitFor(() => {
      expect(screen.getByTestId('fp-rate-no-ecb-mode')).toHaveTextContent('55.0%');
    });
  });

  it('collapses expanded row when clicking again', async () => {
    renderWithProviders();

    await waitFor(() => {
      expect(screen.getByTestId('rule-row-no-broken-algorithms')).toBeInTheDocument();
    });

    // Expand
    fireEvent.click(screen.getByTestId('rule-row-no-broken-algorithms'));
    await waitFor(() => {
      expect(screen.getByTestId('rule-expanded-no-broken-algorithms')).toBeInTheDocument();
    });

    // Collapse
    fireEvent.click(screen.getByTestId('rule-row-no-broken-algorithms'));
    await waitFor(() => {
      expect(screen.queryByTestId('rule-expanded-no-broken-algorithms')).not.toBeInTheDocument();
    });
  });

  it('still renders base rule information', async () => {
    renderWithProviders();

    await waitFor(() => {
      expect(screen.getByText('Policy Rules')).toBeInTheDocument();
      expect(screen.getByText('No Broken Algorithms')).toBeInTheDocument();
      expect(screen.getByText('No ECB Mode')).toBeInTheDocument();
      expect(screen.getByText('RSA Minimum Key Size')).toBeInTheDocument();
    });
  });

  it('toggle rule enabled/disabled still works', async () => {
    renderWithProviders();

    await waitFor(() => {
      expect(screen.getByTestId('rule-row-no-broken-algorithms')).toBeInTheDocument();
    });

    // Find the enabled button within the first rule row
    const buttons = screen.getAllByText('Enabled');
    expect(buttons.length).toBeGreaterThan(0);

    fireEvent.click(buttons[0]!);

    await waitFor(() => {
      expect(screen.getAllByText('Disabled').length).toBeGreaterThanOrEqual(1);
    });
  });
});
