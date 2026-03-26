import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import {
  FindingStatusFilter,
  ALL_STATUSES,
  DEFAULT_ACTIVE_STATUSES,
} from '../../src/components/findings/FindingStatusFilter';

const mockCounts = {
  open: 5,
  in_review: 3,
  in_progress: 2,
  resolved: 10,
  risk_accepted: 1,
  false_positive: 4,
};
const totalCount = 25;

describe('FindingStatusFilter', () => {
  it('renders all status filter buttons with counts', () => {
    const onToggle = vi.fn();
    render(
      <FindingStatusFilter
        counts={mockCounts}
        totalCount={totalCount}
        activeStatuses={[...DEFAULT_ACTIVE_STATUSES]}
        onToggle={onToggle}
      />,
    );

    expect(screen.getByTestId('status-filter-all')).toHaveTextContent('All (25)');
    expect(screen.getByTestId('status-filter-open')).toHaveTextContent('Open (5)');
    expect(screen.getByTestId('status-filter-in_review')).toHaveTextContent('In Review (3)');
    expect(screen.getByTestId('status-filter-in_progress')).toHaveTextContent('In Progress (2)');
    expect(screen.getByTestId('status-filter-resolved')).toHaveTextContent('Resolved (10)');
    expect(screen.getByTestId('status-filter-risk_accepted')).toHaveTextContent('Risk Accepted (1)');
    expect(screen.getByTestId('status-filter-false_positive')).toHaveTextContent('False Positive (4)');
  });

  it('marks default active statuses as active', () => {
    const onToggle = vi.fn();
    render(
      <FindingStatusFilter
        counts={mockCounts}
        totalCount={totalCount}
        activeStatuses={[...DEFAULT_ACTIVE_STATUSES]}
        onToggle={onToggle}
      />,
    );

    // open, in_review, in_progress should be active
    expect(screen.getByTestId('status-filter-open').className).toContain('active');
    expect(screen.getByTestId('status-filter-in_review').className).toContain('active');
    expect(screen.getByTestId('status-filter-in_progress').className).toContain('active');

    // resolved, risk_accepted, false_positive should NOT be active
    expect(screen.getByTestId('status-filter-resolved').className).not.toContain('active');
    expect(screen.getByTestId('status-filter-risk_accepted').className).not.toContain('active');
    expect(screen.getByTestId('status-filter-false_positive').className).not.toContain('active');
  });

  it('calls onToggle with status when individual filter is clicked', () => {
    const onToggle = vi.fn();
    render(
      <FindingStatusFilter
        counts={mockCounts}
        totalCount={totalCount}
        activeStatuses={[...DEFAULT_ACTIVE_STATUSES]}
        onToggle={onToggle}
      />,
    );

    fireEvent.click(screen.getByTestId('status-filter-resolved'));
    expect(onToggle).toHaveBeenCalledWith('resolved');
  });

  it('calls onToggle with "all" when All button is clicked', () => {
    const onToggle = vi.fn();
    render(
      <FindingStatusFilter
        counts={mockCounts}
        totalCount={totalCount}
        activeStatuses={[...DEFAULT_ACTIVE_STATUSES]}
        onToggle={onToggle}
      />,
    );

    fireEvent.click(screen.getByTestId('status-filter-all'));
    expect(onToggle).toHaveBeenCalledWith('all');
  });

  it('marks All as active when all statuses are selected', () => {
    const onToggle = vi.fn();
    render(
      <FindingStatusFilter
        counts={mockCounts}
        totalCount={totalCount}
        activeStatuses={[...ALL_STATUSES]}
        onToggle={onToggle}
      />,
    );

    expect(screen.getByTestId('status-filter-all').className).toContain('active');
  });
});
