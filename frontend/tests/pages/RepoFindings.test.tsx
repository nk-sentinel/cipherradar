import { describe, it, expect } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { RepoFindings } from '../../src/pages/repo/RepoFindings';

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

describe('RepoFindings', () => {
  it('renders finding table with column headers', async () => {
    renderWithProviders(<RepoFindings repoId="repo-1" />);

    await waitFor(() => {
      expect(screen.getByText('Findings')).toBeInTheDocument();
      expect(screen.getByText('Severity')).toBeInTheDocument();
      expect(screen.getByText('File')).toBeInTheDocument();
      expect(screen.getByText('Finding')).toBeInTheDocument();
      expect(screen.getByText('Algorithm')).toBeInTheDocument();
      expect(screen.getByText('Quantum')).toBeInTheDocument();
      expect(screen.getByText('Pass')).toBeInTheDocument();
    });
  });

  it('renders filter buttons', async () => {
    renderWithProviders(<RepoFindings repoId="repo-1" />);

    await waitFor(() => {
      expect(screen.getByText(/^All\s*\(/)).toBeInTheDocument();
      expect(screen.getByText(/^Critical\s*\(/)).toBeInTheDocument();
      expect(screen.getByText(/^High\s*\(/)).toBeInTheDocument();
      expect(screen.getByText(/^Medium\s*\(/)).toBeInTheDocument();
      expect(screen.getByText('Quantum Vulnerable')).toBeInTheDocument();
      // "Broken" appears in both the filter button and as severity badges in the table
      expect(screen.getAllByText('Broken').length).toBeGreaterThanOrEqual(1);
    });
  });

  it('renders finding rows from mock data', async () => {
    renderWithProviders(<RepoFindings repoId="repo-1" />);

    await waitFor(() => {
      expect(screen.getByText('Certificate validation disabled')).toBeInTheDocument();
      expect(screen.getByText('MD5 hash function')).toBeInTheDocument();
      expect(screen.getByText('DES/ECB — broken cipher')).toBeInTheDocument();
      expect(screen.getByText('AES-256-GCM encryption')).toBeInTheDocument();
      expect(screen.getByText('RSA-2048 key generation')).toBeInTheDocument();
    });
  });

  it('renders search input', async () => {
    renderWithProviders(<RepoFindings repoId="repo-1" />);

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Search...')).toBeInTheDocument();
    });
  });
});
