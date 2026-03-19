import type { QuantumStatus } from '@/mocks/data/findings';

const QUANTUM_CLASS: Record<QuantumStatus, string> = {
  vulnerable: 'b-vuln',
  safe: 'b-safe',
  broken: 'b-broken',
  unknown: '',
};

const QUANTUM_LABEL: Record<QuantumStatus, string> = {
  vulnerable: 'Vuln',
  safe: 'Safe',
  broken: 'Broken',
  unknown: 'Unknown',
};

interface QuantumBadgeProps {
  status: QuantumStatus;
  long?: boolean;
}

export function QuantumBadge({ status, long }: QuantumBadgeProps): React.ReactElement {
  const label = long
    ? status.charAt(0).toUpperCase() + status.slice(1)
    : QUANTUM_LABEL[status];

  if (status === 'unknown' && !long) {
    return <span style={{ color: 'var(--text-4)' }}>&mdash;</span>;
  }

  const className = QUANTUM_CLASS[status];

  return (
    <span className={className ? `badge ${className}` : 'badge'}>
      {label}
    </span>
  );
}
