import { cn } from '@/lib/utils.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface PaginationProps {
  page: number;
  perPage: number;
  total: number;
  onPageChange: (page: number) => void;
  onPerPageChange: (perPage: number) => void;
}

const PER_PAGE_OPTIONS = [10, 25, 50, 100];

// ---------------------------------------------------------------------------
// Page range computation with ellipsis
// ---------------------------------------------------------------------------

type PageItem = { type: 'page'; value: number } | { type: 'ellipsis'; key: string };

function getPageItems(current: number, totalPages: number): PageItem[] {
  if (totalPages <= 7) {
    // Show all pages if 7 or fewer
    return Array.from({ length: totalPages }, (_, i) => ({
      type: 'page' as const,
      value: i + 1,
    }));
  }

  const items: PageItem[] = [];

  // Always show page 1
  items.push({ type: 'page', value: 1 });

  if (current > 3) {
    items.push({ type: 'ellipsis', key: 'start' });
  }

  // Window around current page
  const start = Math.max(2, current - 1);
  const end = Math.min(totalPages - 1, current + 1);

  for (let i = start; i <= end; i++) {
    items.push({ type: 'page', value: i });
  }

  if (current < totalPages - 2) {
    items.push({ type: 'ellipsis', key: 'end' });
  }

  // Always show last page
  items.push({ type: 'page', value: totalPages });

  return items;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function Pagination({
  page,
  perPage,
  total,
  onPageChange,
  onPerPageChange,
}: PaginationProps): React.ReactElement {
  const totalPages = Math.max(1, Math.ceil(total / perPage));
  const rangeStart = total === 0 ? 0 : (page - 1) * perPage + 1;
  const rangeEnd = Math.min(page * perPage, total);
  const isFirstPage = page <= 1;
  const isLastPage = page >= totalPages;

  const pageItems = getPageItems(page, totalPages);

  return (
    <nav className="pagination" aria-label="Pagination">
      <span className="pagination-info">
        {`Showing ${rangeStart}\u2013${rangeEnd} of ${total}`}
      </span>

      <div className="pagination-controls">
        <button
          className="btn btn-outline page-nav"
          onClick={() => onPageChange(page - 1)}
          disabled={isFirstPage}
          aria-label="Previous page"
          type="button"
        >
          Previous
        </button>

        <div className="page-numbers">
          {pageItems.map((item) =>
            item.type === 'ellipsis' ? (
              <span key={item.key} className="page-ellipsis" aria-hidden="true">
                {'\u2026'}
              </span>
            ) : (
              <button
                key={item.value}
                className={cn(
                  'page-btn',
                  item.value === page && 'page-btn-active',
                )}
                onClick={() => onPageChange(item.value)}
                aria-label={`Page ${String(item.value)}`}
                aria-current={item.value === page ? 'page' : undefined}
                type="button"
              >
                {item.value}
              </button>
            ),
          )}
        </div>

        <button
          className="btn btn-outline page-nav"
          onClick={() => onPageChange(page + 1)}
          disabled={isLastPage}
          aria-label="Next page"
          type="button"
        >
          Next
        </button>

        <label className="per-page-label">
          <select
            className="per-page-select"
            value={perPage}
            onChange={(e) => onPerPageChange(Number(e.target.value))}
            aria-label="Items per page"
          >
            {PER_PAGE_OPTIONS.map((opt) => (
              <option key={opt} value={opt}>
                {opt}
              </option>
            ))}
          </select>
          <span className="per-page-text">/ page</span>
        </label>
      </div>
    </nav>
  );
}
