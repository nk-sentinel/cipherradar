import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { RequestModal } from '../../src/components/findings/RequestModal';

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

describe('RequestModal', () => {
  it('renders modal with FP type pre-selected', () => {
    const onClose = vi.fn();
    renderWithProviders(
      <RequestModal findingId="f-001" defaultType="false_positive" onClose={onClose} />,
    );

    expect(screen.getByTestId('request-modal')).toBeInTheDocument();
    expect(screen.getByText('Request FP Review')).toBeInTheDocument();
  });

  it('renders modal with RA type pre-selected', () => {
    const onClose = vi.fn();
    renderWithProviders(
      <RequestModal findingId="f-001" defaultType="risk_accepted" onClose={onClose} />,
    );

    expect(screen.getByText('Request Risk Acceptance')).toBeInTheDocument();
    // RA shows reason category and review date
    expect(screen.getByTestId('request-reason-category')).toBeInTheDocument();
    expect(screen.getByTestId('request-review-date')).toBeInTheDocument();
  });

  it('validates justification is required', async () => {
    const onClose = vi.fn();
    renderWithProviders(
      <RequestModal findingId="f-001" defaultType="false_positive" onClose={onClose} />,
    );

    // Try to submit without justification
    fireEvent.click(screen.getByTestId('request-submit'));

    await waitFor(() => {
      expect(screen.getByTestId('request-error')).toHaveTextContent('Justification is required');
    });
  });

  it('validates reason category is required for RA', async () => {
    const onClose = vi.fn();
    renderWithProviders(
      <RequestModal findingId="f-001" defaultType="risk_accepted" onClose={onClose} />,
    );

    // Fill justification but not reason category
    fireEvent.change(screen.getByTestId('request-justification'), {
      target: { value: 'Test justification' },
    });
    fireEvent.click(screen.getByTestId('request-submit'));

    await waitFor(() => {
      expect(screen.getByTestId('request-error')).toHaveTextContent(
        'Reason category is required',
      );
    });
  });

  it('calls onClose when close button is clicked', () => {
    const onClose = vi.fn();
    renderWithProviders(
      <RequestModal findingId="f-001" defaultType="false_positive" onClose={onClose} />,
    );

    fireEvent.click(screen.getByText('Close'));
    expect(onClose).toHaveBeenCalled();
  });
});
