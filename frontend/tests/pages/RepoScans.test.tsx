import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { RepoScans } from '../../src/pages/repo/RepoScans';

// Mock recharts to avoid DOM measurement issues in jsdom
vi.mock('recharts', () => ({
  BarChart: ({ children }: { children: React.ReactNode }) => <div data-testid="bar-chart">{children}</div>,
  Bar: () => <div />,
  XAxis: () => <div />,
  YAxis: () => <div />,
  Tooltip: () => <div />,
  ResponsiveContainer: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  Cell: () => <div />,
}));

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        {children}
      </QueryClientProvider>
    );
  };
}

describe('RepoScans', () => {
  it('renders severity stat counts for a valid scan', async () => {
    render(<RepoScans scanId="scan-47" />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByTestId('stat-critical')).toHaveTextContent('5');
    });

    expect(screen.getByTestId('stat-high')).toHaveTextContent('28');
    expect(screen.getByTestId('stat-medium')).toHaveTextContent('67');
    expect(screen.getByTestId('stat-low-info')).toHaveTextContent('242');
  });

  it('renders scan header with branch and commit', async () => {
    render(<RepoScans scanId="scan-47" />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText(/Scan #47/)).toBeInTheDocument();
    });

    expect(screen.getByText(/main/)).toBeInTheDocument();
    expect(screen.getByText(/a2b2fbc/)).toBeInTheDocument();
  });

  it('renders export buttons', async () => {
    render(<RepoScans scanId="scan-47" />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText('CBOM')).toBeInTheDocument();
    });

    expect(screen.getByText('SARIF')).toBeInTheDocument();
    expect(screen.getByText('PDF')).toBeInTheDocument();
  });

  it('renders findings table with severity badges', async () => {
    render(<RepoScans scanId="scan-47" />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText('Top Findings')).toBeInTheDocument();
    });

    // Check that findings from mock data appear
    expect(screen.getByText('Certificate validation disabled')).toBeInTheDocument();
    expect(screen.getByText('SSLConfig.java')).toBeInTheDocument();
  });

  it('shows loading state initially', () => {
    render(<RepoScans scanId="scan-47" />, { wrapper: createWrapper() });
    expect(screen.getByText('Loading scan details...')).toBeInTheDocument();
  });

  it('shows error state for invalid scan', async () => {
    render(<RepoScans scanId="nonexistent" />, { wrapper: createWrapper() });

    await waitFor(() => {
      expect(screen.getByText('Scan not found.')).toBeInTheDocument();
    });
  });
});
