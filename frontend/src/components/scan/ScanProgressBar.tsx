import { cn } from '@/lib/utils';

const STAGE_LABELS: Record<string, string> = {
  queued: 'Queued',
  cloning: 'Cloning',
  scanning_pass1: 'Scanning (Pass 1)',
  scanning_pass2: 'Scanning (Pass 2)',
  generating_cbom: 'Generating CBOM',
  completed: 'Complete',
  failed: 'Failed',
};

interface ScanProgressBarProps {
  status: string;
  progressPct: number;
  detail?: string;
  isComplete: boolean;
  isError: boolean;
}

function getBarColor(isComplete: boolean, isError: boolean): string {
  if (isError) return 'var(--red)';
  if (isComplete) return 'var(--green)';
  return 'var(--accent)';
}

export function ScanProgressBar({
  status,
  progressPct,
  detail,
  isComplete,
  isError,
}: ScanProgressBarProps): React.ReactElement {
  const label = STAGE_LABELS[status] ?? status;
  const pct = isError ? 100 : Math.max(0, Math.min(100, progressPct));

  return (
    <div data-testid="scan-progress-bar" className="scan-progress">
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '6px',
        }}
      >
        <span
          data-testid="scan-progress-stage"
          className={cn(
            isError && 'text-error',
            isComplete && 'text-success',
          )}
          style={{
            fontSize: '12px',
            fontWeight: 600,
            color: isError ? 'var(--red)' : isComplete ? 'var(--green)' : 'var(--text-1)',
          }}
        >
          {label}
        </span>
        <span
          data-testid="scan-progress-pct"
          style={{ fontSize: '11px', color: 'var(--text-3)' }}
        >
          {isError ? '' : `${String(pct)}%`}
        </span>
      </div>

      <div
        className="progress"
        style={{
          height: '6px',
          borderRadius: '3px',
          background: 'var(--bg-3)',
          overflow: 'hidden',
        }}
      >
        <div
          data-testid="scan-progress-fill"
          className="progress-fill"
          style={{
            width: `${String(pct)}%`,
            height: '100%',
            background: getBarColor(isComplete, isError),
            borderRadius: '3px',
            transition: 'width 0.4s ease, background 0.3s ease',
          }}
        />
      </div>

      {detail && (
        <div
          data-testid="scan-progress-detail"
          style={{ fontSize: '11px', color: 'var(--text-3)', marginTop: '4px' }}
        >
          {detail}
        </div>
      )}
    </div>
  );
}
