import type { FindingStatus } from '@/mocks/data/findings';

const STATUS_CLASS: Record<FindingStatus, string> = {
  open: 'b-crit',
  in_review: 'b-high',
  in_progress: 'b-info',
  resolved: 'b-safe',
  risk_accepted: 'b-purple',
  false_positive: 'b-gray',
};

const STATUS_LABEL: Record<FindingStatus, string> = {
  open: 'Open',
  in_review: 'In Review',
  in_progress: 'In Progress',
  resolved: 'Resolved',
  risk_accepted: 'Risk Accepted',
  false_positive: 'False Positive',
};

export function formatStatus(status: FindingStatus): string {
  return STATUS_LABEL[status] ?? status;
}

interface FindingStatusBadgeProps {
  status: FindingStatus;
}

export function FindingStatusBadge({ status }: FindingStatusBadgeProps): React.ReactElement {
  const cls = STATUS_CLASS[status] ?? 'b-gray';
  return (
    <span className={`badge ${cls}`} data-testid={`status-badge-${status}`}>
      {formatStatus(status)}
    </span>
  );
}
