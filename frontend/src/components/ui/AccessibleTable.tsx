import { useRef, useCallback, type ReactNode } from 'react';
import { cn } from '@/lib/utils.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AccessibleColumn {
  /** Header label text */
  label: string;
  /** Optional className for the <th> */
  className?: string;
}

export interface AccessibleTableProps {
  /** Column definitions — each header gets scope="col" automatically */
  columns: AccessibleColumn[];
  /** Table body content (rendered inside <tbody>) */
  children: ReactNode;
  /** Optional caption for screen readers */
  caption?: string;
  /** Optional className for the <table> element */
  className?: string;
  /** Optional data-testid */
  'data-testid'?: string;
}

// ---------------------------------------------------------------------------
// Keyboard navigation helpers
// ---------------------------------------------------------------------------

/**
 * Move focus between rows using arrow keys.
 * - ArrowDown: focus the same-column cell in the next row
 * - ArrowUp:   focus the same-column cell in the previous row
 * - Home:      focus the first row
 * - End:       focus the last row
 */
function handleTableKeyDown(
  event: React.KeyboardEvent<HTMLTableSectionElement>,
  tbodyRef: React.RefObject<HTMLTableSectionElement | null>,
): void {
  const tbody = tbodyRef.current;
  if (!tbody) return;

  const rows = Array.from(tbody.querySelectorAll('tr'));
  if (rows.length === 0) return;

  const currentRow = (event.target as HTMLElement).closest('tr');
  if (!currentRow) return;

  const currentIndex = rows.indexOf(currentRow as HTMLTableRowElement);
  if (currentIndex === -1) return;

  let targetIndex: number | null = null;

  switch (event.key) {
    case 'ArrowDown':
      event.preventDefault();
      targetIndex = Math.min(currentIndex + 1, rows.length - 1);
      break;
    case 'ArrowUp':
      event.preventDefault();
      targetIndex = Math.max(currentIndex - 1, 0);
      break;
    case 'Home':
      event.preventDefault();
      targetIndex = 0;
      break;
    case 'End':
      event.preventDefault();
      targetIndex = rows.length - 1;
      break;
    default:
      return;
  }

  if (targetIndex !== null && rows[targetIndex]) {
    const targetRow = rows[targetIndex] as HTMLTableRowElement;
    targetRow.focus();
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * Accessible table wrapper that:
 * - Adds `scope="col"` to all <th> elements
 * - Enables keyboard navigation (Arrow Up/Down, Home, End) across rows
 * - Supports optional <caption> for screen readers
 * - Wraps content in a responsive scroll container
 */
export function AccessibleTable({
  columns,
  children,
  caption,
  className,
  'data-testid': testId,
}: AccessibleTableProps): React.ReactElement {
  const tbodyRef = useRef<HTMLTableSectionElement | null>(null);

  const onKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLTableSectionElement>) => {
      handleTableKeyDown(event, tbodyRef);
    },
    [],
  );

  return (
    <div className="table-responsive">
      <table className={cn(className)} data-testid={testId}>
        {caption && <caption className="sr-only">{caption}</caption>}
        <thead>
          <tr>
            {columns.map((col) => (
              <th key={col.label} scope="col" className={col.className}>
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody ref={tbodyRef} onKeyDown={onKeyDown}>
          {children}
        </tbody>
      </table>
    </div>
  );
}
