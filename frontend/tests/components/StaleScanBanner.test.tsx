import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { StaleScanBanner } from '../../src/components/scan/StaleScanBanner';

describe('StaleScanBanner', () => {
  it('shows banner when scan is stale', () => {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const onAction = vi.fn();

    render(
      <StaleScanBanner lastScanDate={thirtyDaysAgo} staleDays={14} onAction={onAction} />,
    );

    expect(screen.getByTestId('stale-scan-banner')).toBeInTheDocument();
    expect(screen.getByText(/30 days ago/)).toBeInTheDocument();
  });

  it('is hidden when scan is recent', () => {
    const twoDaysAgo = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString();
    const onAction = vi.fn();

    const { container } = render(
      <StaleScanBanner lastScanDate={twoDaysAgo} staleDays={14} onAction={onAction} />,
    );

    expect(container.innerHTML).toBe('');
  });

  it('calls action handler when button is clicked', () => {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const onAction = vi.fn();

    render(
      <StaleScanBanner lastScanDate={thirtyDaysAgo} staleDays={14} onAction={onAction} />,
    );

    fireEvent.click(screen.getByTestId('stale-scan-action'));
    expect(onAction).toHaveBeenCalledOnce();
  });

  it('returns null when no lastScanDate', () => {
    const onAction = vi.fn();
    const { container } = render(
      <StaleScanBanner onAction={onAction} />,
    );

    expect(container.innerHTML).toBe('');
  });

  it('uses custom staleDays threshold', () => {
    const fiveDaysAgo = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString();
    const onAction = vi.fn();

    render(
      <StaleScanBanner lastScanDate={fiveDaysAgo} staleDays={3} onAction={onAction} />,
    );

    expect(screen.getByTestId('stale-scan-banner')).toBeInTheDocument();
  });
});
