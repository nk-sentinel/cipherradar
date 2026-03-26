import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { FindingStatusBadge } from '../../src/components/findings/FindingStatusBadge';
import type { FindingStatus } from '../../src/mocks/data/findings';

const ALL_VARIANTS: { status: FindingStatus; label: string; expectedClass: string }[] = [
  { status: 'open', label: 'Open', expectedClass: 'b-crit' },
  { status: 'in_review', label: 'In Review', expectedClass: 'b-high' },
  { status: 'in_progress', label: 'In Progress', expectedClass: 'b-info' },
  { status: 'resolved', label: 'Resolved', expectedClass: 'b-safe' },
  { status: 'risk_accepted', label: 'Risk Accepted', expectedClass: 'b-purple' },
  { status: 'false_positive', label: 'False Positive', expectedClass: 'b-gray' },
];

describe('FindingStatusBadge', () => {
  it('renders all status variants with correct labels', () => {
    for (const { status, label } of ALL_VARIANTS) {
      const { unmount } = render(<FindingStatusBadge status={status} />);
      expect(screen.getByText(label)).toBeInTheDocument();
      unmount();
    }
  });

  it('applies the correct CSS class for each variant', () => {
    for (const { status, expectedClass } of ALL_VARIANTS) {
      const { unmount } = render(<FindingStatusBadge status={status} />);
      const badge = screen.getByTestId(`status-badge-${status}`);
      expect(badge.className).toContain(expectedClass);
      unmount();
    }
  });

  it('always includes the base badge class', () => {
    for (const { status } of ALL_VARIANTS) {
      const { unmount } = render(<FindingStatusBadge status={status} />);
      const badge = screen.getByTestId(`status-badge-${status}`);
      expect(badge.className).toContain('badge');
      unmount();
    }
  });
});
