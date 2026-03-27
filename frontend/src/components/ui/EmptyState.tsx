import type { ReactNode } from 'react';

export interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
}

export function EmptyState({
  icon,
  title,
  description,
  actionLabel,
  onAction,
}: EmptyStateProps): React.ReactElement {
  return (
    <div
      data-testid="empty-state"
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '48px 24px',
        textAlign: 'center',
      }}
    >
      {icon && (
        <div
          data-testid="empty-state-icon"
          style={{
            fontSize: '48px',
            marginBottom: '16px',
            color: 'var(--text-4)',
            lineHeight: 1,
          }}
        >
          {icon}
        </div>
      )}
      <h3
        data-testid="empty-state-title"
        style={{
          fontSize: '16px',
          fontWeight: 600,
          color: 'var(--text-1)',
          marginBottom: '8px',
        }}
      >
        {title}
      </h3>
      <p
        data-testid="empty-state-description"
        style={{
          fontSize: '13px',
          color: 'var(--text-3)',
          maxWidth: '400px',
          lineHeight: 1.5,
          marginBottom: actionLabel ? '20px' : '0',
        }}
      >
        {description}
      </p>
      {actionLabel && onAction && (
        <button
          className="btn btn-accent"
          onClick={onAction}
          data-testid="empty-state-action"
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
}

/**
 * Guest banner — dismissable info bar for view-only access (#55).
 */
export interface GuestBannerProps {
  onDismiss?: () => void;
}

export function GuestBanner({ onDismiss }: GuestBannerProps): React.ReactElement {
  return (
    <div
      data-testid="guest-banner"
      className="alert alert-warn"
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: '16px',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span style={{ fontSize: '14px' }}>{'\u2139'}</span>
        <span style={{ fontSize: '12px' }}>
          You have view-only access. Contact your admin to request additional permissions.
        </span>
      </div>
      {onDismiss && (
        <button
          onClick={onDismiss}
          data-testid="guest-banner-dismiss"
          aria-label="Dismiss guest banner"
          style={{
            background: 'none',
            border: 'none',
            color: 'var(--accent)',
            cursor: 'pointer',
            fontSize: '16px',
            lineHeight: 1,
            padding: '0 4px',
          }}
        >
          {'\u2715'}
        </button>
      )}
    </div>
  );
}
