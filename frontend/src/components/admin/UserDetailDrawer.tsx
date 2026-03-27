import { ROLE_LABELS } from '@/lib/roles.ts';
import type { ManagedUser } from '@/api/hooks/useUserManagement.ts';
import { useDisableUser, useEnableUser } from '@/api/hooks/useUserManagement.ts';

interface UserDetailDrawerProps {
  user: ManagedUser;
  onClose: () => void;
}

export function UserDetailDrawer({ user, onClose }: UserDetailDrawerProps): React.ReactElement {
  const disableUser = useDisableUser();
  const enableUser = useEnableUser();

  const getStaleColor = (lastActive: string): string | undefined => {
    // Simple heuristic: if contains "day" or "days" and the number is > 90
    const daysMatch = lastActive.match(/(\d+)\s*days?\s*ago/i);
    if (daysMatch) {
      const days = parseInt(daysMatch[1] ?? '0', 10);
      if (days > 90) return 'var(--red)';
      if (days > 30) return 'var(--yellow)';
    }
    if (lastActive === 'Never') return 'var(--red)';
    return undefined;
  };

  return (
    <div
      data-testid="user-detail-drawer"
      style={{
        position: 'fixed',
        top: 0,
        right: 0,
        bottom: 0,
        width: '420px',
        background: 'var(--surface-1)',
        borderLeft: '1px solid var(--border)',
        boxShadow: '-4px 0 24px rgba(0,0,0,0.3)',
        zIndex: 200,
        display: 'flex',
        flexDirection: 'column',
        overflow: 'auto',
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}
      >
        <h2 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-1)' }}>
          User Details
        </h2>
        <button
          className="btn btn-outline"
          onClick={onClose}
          data-testid="drawer-close"
          style={{ fontSize: '11px', padding: '4px 10px' }}
        >
          Close
        </button>
      </div>

      {/* Content */}
      <div style={{ padding: '20px', flex: 1 }}>
        {/* Profile */}
        <div style={{ marginBottom: '20px' }}>
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '50%',
              background: 'var(--accent-dim)',
              color: 'var(--accent)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontWeight: 700,
              fontSize: '16px',
              marginBottom: '12px',
            }}
          >
            {user.name
              .split(' ')
              .map((w) => w[0])
              .join('')
              .toUpperCase()
              .slice(0, 2)}
          </div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-1)' }}>
            {user.name}
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-2)', marginTop: '2px' }}>
            {user.email}
          </div>
        </div>

        {/* Details */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <DetailRow label="Role" value={ROLE_LABELS[user.role]} />
          <DetailRow label="Auth Source" value={user.authSource} />
          <DetailRow
            label="Status"
            value={
              <span
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px',
                }}
              >
                <span
                  style={{
                    width: '6px',
                    height: '6px',
                    borderRadius: '50%',
                    background:
                      user.status === 'active'
                        ? 'var(--green)'
                        : user.status === 'invited'
                          ? 'var(--yellow)'
                          : 'var(--red)',
                  }}
                />
                {user.status.charAt(0).toUpperCase() + user.status.slice(1)}
              </span>
            }
          />
          <DetailRow
            label="Last Active"
            value={
              <span style={{ color: getStaleColor(user.lastActive) }}>
                {user.lastActive}
              </span>
            }
          />
          <DetailRow label="Member Since" value={user.createdAt} />
          <DetailRow
            label="Groups"
            value={
              user.groups.length > 0
                ? user.groups.map((g) => g.name).join(', ')
                : 'None'
            }
          />
          <DetailRow label="API Keys" value={String(user.apiKeyCount)} />
        </div>

        {/* Quick Actions */}
        <div style={{ marginTop: '24px', borderTop: '1px solid var(--border)', paddingTop: '16px' }}>
          <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-2)', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Quick Actions
          </div>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            {user.status === 'active' && (
              <button
                className="btn btn-outline"
                style={{ fontSize: '11px', color: 'var(--yellow)' }}
                data-testid="drawer-disable-btn"
                disabled={disableUser.isPending}
                onClick={() => disableUser.mutate(user.id)}
              >
                {disableUser.isPending ? 'Disabling...' : 'Disable User'}
              </button>
            )}
            {user.status === 'disabled' && (
              <button
                className="btn btn-outline"
                style={{ fontSize: '11px', color: 'var(--green)' }}
                data-testid="drawer-enable-btn"
                disabled={enableUser.isPending}
                onClick={() => enableUser.mutate(user.id)}
              >
                {enableUser.isPending ? 'Enabling...' : 'Enable User'}
              </button>
            )}
            {user.authSource === 'local' && (
              <button
                className="btn btn-outline"
                style={{ fontSize: '11px' }}
                data-testid="drawer-reset-password-btn"
                onClick={() => {
                  // placeholder for Phase 4.5
                }}
              >
                Reset Password
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function DetailRow({
  label,
  value,
}: {
  label: string;
  value: React.ReactNode;
}): React.ReactElement {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
      <span style={{ fontSize: '11px', color: 'var(--text-3)', fontWeight: 500 }}>{label}</span>
      <span style={{ fontSize: '12px', color: 'var(--text-1)' }}>{value}</span>
    </div>
  );
}
