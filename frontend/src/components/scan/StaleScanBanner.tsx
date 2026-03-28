interface StaleScanBannerProps {
  /** ISO date string of the last scan, or undefined if no scans exist */
  lastScanDate?: string;
  /** Number of days before showing the warning (default: 30) */
  staleDays?: number;
  /** Action handler for the "Scan Now" button */
  onAction: () => void;
}

function getDaysAgo(dateStr: string): number {
  const diff = Date.now() - new Date(dateStr).getTime();
  return Math.floor(diff / (1000 * 60 * 60 * 24));
}

export function StaleScanBanner({
  lastScanDate,
  staleDays = 30,
  onAction,
}: StaleScanBannerProps): React.ReactElement | null {
  if (!lastScanDate) return null;

  const daysAgo = getDaysAgo(lastScanDate);
  if (daysAgo < staleDays) return null;

  return (
    <div
      data-testid="stale-scan-banner"
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '10px 16px',
        marginBottom: '16px',
        background: 'rgba(245, 158, 11, 0.1)',
        border: '1px solid var(--amber)',
        borderRadius: 'var(--radius)',
        fontSize: '13px',
        color: 'var(--text-1)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span style={{ color: 'var(--amber)', fontSize: '16px' }}>&#9888;</span>
        <span>
          Last scan was <strong>{daysAgo} days ago</strong>. Consider running a new scan to check for changes.
        </span>
      </div>
      <button
        data-testid="stale-scan-action"
        className="btn btn-accent"
        onClick={onAction}
        type="button"
        style={{ fontSize: '12px', padding: '4px 12px', whiteSpace: 'nowrap' }}
      >
        Scan Now
      </button>
    </div>
  );
}
