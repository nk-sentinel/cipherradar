import { cn } from '@/lib/utils';
import type { FindingStatus } from '@/mocks/data/findings';

export const ALL_STATUSES: FindingStatus[] = [
  'open',
  'in_review',
  'in_progress',
  'resolved',
  'risk_accepted',
  'false_positive',
];

export const DEFAULT_ACTIVE_STATUSES: FindingStatus[] = [
  'open',
  'in_review',
  'in_progress',
];

const STATUS_LABELS: Record<FindingStatus, string> = {
  open: 'Open',
  in_review: 'In Review',
  in_progress: 'In Progress',
  resolved: 'Resolved',
  risk_accepted: 'Risk Accepted',
  false_positive: 'False Positive',
};

interface StatusCounts {
  open: number;
  in_review: number;
  in_progress: number;
  resolved: number;
  risk_accepted: number;
  false_positive: number;
}

interface FindingStatusFilterProps {
  counts: StatusCounts;
  totalCount: number;
  activeStatuses: FindingStatus[];
  onToggle: (status: FindingStatus | 'all') => void;
}

export function FindingStatusFilter({
  counts,
  totalCount,
  activeStatuses,
  onToggle,
}: FindingStatusFilterProps): React.ReactElement {
  const allActive = activeStatuses.length === ALL_STATUSES.length;

  return (
    <div className="filters" data-testid="status-filter-bar">
      <button
        className={cn('filter', allActive && 'active')}
        onClick={() => onToggle('all')}
        data-testid="status-filter-all"
      >
        All ({totalCount})
      </button>
      {ALL_STATUSES.map((status) => (
        <button
          key={status}
          className={cn('filter', activeStatuses.includes(status) && 'active')}
          onClick={() => onToggle(status)}
          data-testid={`status-filter-${status}`}
        >
          {STATUS_LABELS[status]} ({counts[status]})
        </button>
      ))}
    </div>
  );
}
