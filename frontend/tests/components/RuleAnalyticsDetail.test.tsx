import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { RuleAnalyticsDetail } from '../../src/components/rules/RuleAnalyticsDetail';

const MOCK_ANALYTICS = {
  ruleId: 'cbom-python-md5-usage',
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

const MOCK_HIGH_FP_ANALYTICS = {
  ...MOCK_ANALYTICS,
  ruleId: 'cbom-java-weak-rsa',
  fpRate: 55.0,
  fixRate: 8.0,
  mttrSeconds: null,
};

const server = setupServer(
  http.get('/api/v1/admin/rules/:ruleId/analytics', ({ params }) => {
    const ruleId = params['ruleId'] as string;
    if (ruleId === 'cbom-java-weak-rsa') {
      return HttpResponse.json(MOCK_HIGH_FP_ANALYTICS);
    }
    return HttpResponse.json(MOCK_ANALYTICS);
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }));
afterEach(() => server.resetHandlers());
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

describe('RuleAnalyticsDetail', () => {
  it('renders analytics stats', async () => {
    renderWithProviders(
      <RuleAnalyticsDetail ruleId="cbom-python-md5-usage" timeWindow="90d" />,
    );

    await waitFor(() => {
      expect(screen.getByTestId('rule-analytics-detail')).toBeInTheDocument();
    });

    expect(screen.getByTestId('analytics-total')).toHaveTextContent('42');
    expect(screen.getByTestId('analytics-fp-rate')).toHaveTextContent('12.5%');
    expect(screen.getByTestId('analytics-fix-rate')).toHaveTextContent('60.0%');
    expect(screen.getByTestId('analytics-mttr')).toHaveTextContent('2d 0h');
  });

  it('renders trend chart', async () => {
    renderWithProviders(
      <RuleAnalyticsDetail ruleId="cbom-python-md5-usage" timeWindow="90d" />,
    );

    await waitFor(() => {
      expect(screen.getByTestId('analytics-trend-chart')).toBeInTheDocument();
    });
  });

  it('shows "Valuable" signal label for low FP + high fix', async () => {
    renderWithProviders(
      <RuleAnalyticsDetail ruleId="cbom-python-md5-usage" timeWindow="90d" />,
    );

    await waitFor(() => {
      expect(screen.getByTestId('analytics-signal')).toHaveTextContent('Valuable');
    });
  });

  it('shows "Pure noise" signal label for high FP + low fix', async () => {
    renderWithProviders(
      <RuleAnalyticsDetail ruleId="cbom-java-weak-rsa" timeWindow="90d" />,
    );

    await waitFor(() => {
      expect(screen.getByTestId('analytics-signal')).toHaveTextContent('Pure noise');
    });
  });

  it('shows N/A for null MTTR', async () => {
    renderWithProviders(
      <RuleAnalyticsDetail ruleId="cbom-java-weak-rsa" timeWindow="90d" />,
    );

    await waitFor(() => {
      expect(screen.getByTestId('analytics-mttr')).toHaveTextContent('N/A');
    });
  });
});
