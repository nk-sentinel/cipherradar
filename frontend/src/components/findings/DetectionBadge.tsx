import type { DetectionPass } from '@/mocks/data/findings';

const DETECTION_LABELS: Record<DetectionPass, string> = {
  1: 'Pattern',
  2: 'Taint',
  3: 'Taint',
};

const DETECTION_TITLES: Record<DetectionPass, string> = {
  1: 'Detected via tree-sitter pattern matching (Pass 1)',
  2: 'Detected via OpenGrep taint analysis (Pass 2)',
  3: 'Detected via taint analysis (Pass 3)',
};

interface DetectionBadgeProps {
  pass: DetectionPass;
}

export function DetectionBadge({ pass }: DetectionBadgeProps): React.ReactElement {
  const label = DETECTION_LABELS[pass] ?? `Pass ${String(pass)}`;
  const title = DETECTION_TITLES[pass] ?? `Detection pass ${String(pass)}`;

  return (
    <span
      className={`badge ${pass === 1 ? 'b-info' : 'b-taint'}`}
      title={title}
      data-testid={`detection-badge-${String(pass)}`}
    >
      {label}
    </span>
  );
}
