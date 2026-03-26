import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Pagination } from '../../src/components/ui/Pagination.tsx';

describe('Pagination', () => {
  const defaultProps = {
    page: 1,
    perPage: 25,
    total: 100,
    onPageChange: vi.fn(),
    onPerPageChange: vi.fn(),
  };

  it('renders "Showing X-Y of Z" text', () => {
    render(<Pagination {...defaultProps} />);
    expect(screen.getByText(/Showing 1\u201325 of 100/)).toBeInTheDocument();
  });

  it('shows correct range on page 2', () => {
    render(<Pagination {...defaultProps} page={2} />);
    expect(screen.getByText(/Showing 26\u201350 of 100/)).toBeInTheDocument();
  });

  it('clamps end range on last page', () => {
    render(<Pagination {...defaultProps} page={4} total={90} />);
    // page 4 with perPage 25: 76-90
    expect(screen.getByText(/Showing 76\u201390 of 90/)).toBeInTheDocument();
  });

  it('calls onPageChange when Next is clicked', () => {
    const onPageChange = vi.fn();
    render(<Pagination {...defaultProps} onPageChange={onPageChange} />);
    fireEvent.click(screen.getByRole('button', { name: /next/i }));
    expect(onPageChange).toHaveBeenCalledWith(2);
  });

  it('calls onPageChange when Previous is clicked', () => {
    const onPageChange = vi.fn();
    render(
      <Pagination {...defaultProps} page={3} onPageChange={onPageChange} />,
    );
    fireEvent.click(screen.getByRole('button', { name: /previous/i }));
    expect(onPageChange).toHaveBeenCalledWith(2);
  });

  it('disables Previous on first page', () => {
    render(<Pagination {...defaultProps} page={1} />);
    expect(screen.getByRole('button', { name: /previous/i })).toBeDisabled();
  });

  it('disables Next on last page', () => {
    render(<Pagination {...defaultProps} page={4} />);
    expect(screen.getByRole('button', { name: /next/i })).toBeDisabled();
  });

  it('calls onPageChange when a page number is clicked', () => {
    const onPageChange = vi.fn();
    render(
      <Pagination
        {...defaultProps}
        total={500}
        onPageChange={onPageChange}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Page 2' }));
    expect(onPageChange).toHaveBeenCalledWith(2);
  });

  it('renders per-page selector with correct options', () => {
    render(<Pagination {...defaultProps} />);
    const select = screen.getByRole('combobox', { name: /per page/i });
    expect(select).toBeInTheDocument();
    expect(select).toHaveValue('25');
  });

  it('calls onPerPageChange when per-page is changed', () => {
    const onPerPageChange = vi.fn();
    render(
      <Pagination {...defaultProps} onPerPageChange={onPerPageChange} />,
    );
    const select = screen.getByRole('combobox', { name: /per page/i });
    fireEvent.change(select, { target: { value: '50' } });
    expect(onPerPageChange).toHaveBeenCalledWith(50);
  });

  it('shows ellipsis for large page ranges', () => {
    render(<Pagination {...defaultProps} total={500} page={10} />);
    // With 500 items / 25 per page = 20 pages, current page 10
    // Should show: 1 ... 9 10 11 ... 20
    const ellipses = screen.getAllByText('\u2026');
    expect(ellipses.length).toBeGreaterThanOrEqual(1);
  });

  it('shows page 1 and last page always', () => {
    render(<Pagination {...defaultProps} total={500} page={10} />);
    expect(screen.getByRole('button', { name: 'Page 1' })).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Page 20' }),
    ).toBeInTheDocument();
  });

  it('highlights current page', () => {
    render(<Pagination {...defaultProps} page={2} />);
    const currentBtn = screen.getByRole('button', { name: 'Page 2' });
    expect(currentBtn).toHaveClass('page-btn-active');
  });

  it('handles single page (no navigation needed)', () => {
    render(<Pagination {...defaultProps} total={10} />);
    expect(screen.getByRole('button', { name: /previous/i })).toBeDisabled();
    expect(screen.getByRole('button', { name: /next/i })).toBeDisabled();
  });

  it('handles zero total gracefully', () => {
    render(<Pagination {...defaultProps} total={0} />);
    expect(screen.getByText(/Showing 0\u20130 of 0/)).toBeInTheDocument();
  });

  it('is keyboard accessible — page buttons are tabbable', () => {
    render(<Pagination {...defaultProps} />);
    const buttons = screen.getAllByRole('button');
    buttons.forEach((btn) => {
      // All buttons should be focusable (tabIndex not -1)
      expect(btn.tabIndex).not.toBe(-1);
    });
  });
});
