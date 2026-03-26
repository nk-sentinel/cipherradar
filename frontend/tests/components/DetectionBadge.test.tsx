import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { DetectionBadge } from '../../src/components/findings/DetectionBadge';

describe('DetectionBadge', () => {
  it('renders "Pattern" for pass 1', () => {
    render(<DetectionBadge pass={1} />);
    expect(screen.getByText('Pattern')).toBeInTheDocument();
  });

  it('renders "Taint" for pass 2', () => {
    render(<DetectionBadge pass={2} />);
    expect(screen.getByText('Taint')).toBeInTheDocument();
  });

  it('applies b-info class for pattern detection', () => {
    render(<DetectionBadge pass={1} />);
    const badge = screen.getByTestId('detection-badge-1');
    expect(badge.className).toContain('b-info');
  });

  it('applies b-taint class for taint detection', () => {
    render(<DetectionBadge pass={2} />);
    const badge = screen.getByTestId('detection-badge-2');
    expect(badge.className).toContain('b-taint');
  });

  it('has descriptive title attribute', () => {
    render(<DetectionBadge pass={1} />);
    const badge = screen.getByTestId('detection-badge-1');
    expect(badge.getAttribute('title')).toContain('tree-sitter');
  });
});
