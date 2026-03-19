import type { Severity } from '@/mocks/data/findings';

const SEVERITY_CLASS: Record<Severity, string> = {
  critical: 'b-crit',
  high: 'b-high',
  medium: 'b-med',
  low: 'b-safe',
  info: 'b-safe',
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'CRIT',
  high: 'HIGH',
  medium: 'MED',
  low: 'LOW',
  info: 'INFO',
};

interface SeverityBadgeProps {
  severity: Severity;
  long?: boolean;
}

export function SeverityBadge({ severity, long }: SeverityBadgeProps): React.ReactElement {
  const label = long
    ? severity.charAt(0).toUpperCase() + severity.slice(1)
    : SEVERITY_LABEL[severity];

  return (
    <span className={`badge ${SEVERITY_CLASS[severity]}`}>
      {label}
    </span>
  );
}
