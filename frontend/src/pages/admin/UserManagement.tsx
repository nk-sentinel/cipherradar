import { useState } from 'react';
import { RequireRole } from '@/components/guards/RequireRole.tsx';
import { useOrgUsers } from '@/api/hooks/useAdmin.ts';
import { ROLE_LABELS, type Role } from '@/lib/roles.ts';

export function UserManagement(): React.ReactElement {
  return (
    <RequireRole roles={['org-admin', 'security-manager']}>
      <UserManagementContent />
    </RequireRole>
  );
}

function UserManagementContent(): React.ReactElement {
  const { data, isLoading, error } = useOrgUsers();
  const [showInvite, setShowInvite] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<Role>('developer');

  if (isLoading) {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading...</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="card">
        <p style={{ color: 'var(--red)', fontSize: '13px' }}>
          Failed to load user list.
        </p>
      </div>
    );
  }

  return (
    <div>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '20px',
        }}
      >
        <h1
          style={{
            fontSize: '18px',
            fontWeight: 700,
            textTransform: 'var(--tt)' as React.CSSProperties['textTransform'],
            letterSpacing: '0.04em',
          }}
        >
          User Management
        </h1>
        <button className="btn btn-accent" onClick={() => setShowInvite(!showInvite)}>
          + Invite User
        </button>
      </div>

      {/* Invite form */}
      {showInvite && (
        <div className="card" style={{ marginBottom: '16px' }}>
          <div className="card-title">Invite New User</div>
          <div className="g2" style={{ marginBottom: '8px' }}>
            <div className="field">
              <label className="field-label">Email Address</label>
              <input
                className="input"
                type="email"
                placeholder="user@company.com"
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
              />
            </div>
            <div className="field">
              <label className="field-label">Role</label>
              <select
                className="input"
                value={inviteRole}
                onChange={(e) => setInviteRole(e.target.value as Role)}
              >
                {(Object.entries(ROLE_LABELS) as [Role, string][]).map(([key, label]) => (
                  <option key={key} value={key}>
                    {label}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <button className="btn btn-accent">Send Invite</button>
        </div>
      )}

      {/* User table */}
      <div className="card">
        <div className="card-title">
          Users ({data.length})
        </div>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Email</th>
              <th>Role</th>
              <th>Last Active</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {data.map((user) => (
              <tr key={user.id}>
                <td>
                  <strong>{user.name}</strong>
                </td>
                <td style={{ color: 'var(--text-2)' }}>{user.email}</td>
                <td>
                  <span
                    style={{
                      padding: '2px 8px',
                      borderRadius: 'var(--radius)',
                      fontSize: '10px',
                      fontWeight: 600,
                      background: 'var(--accent-dim)',
                      color: 'var(--accent)',
                      border: '1px solid var(--border)',
                    }}
                  >
                    {ROLE_LABELS[user.role]}
                  </span>
                </td>
                <td style={{ color: 'var(--text-3)', fontSize: '11px' }}>{user.lastActive}</td>
                <td>
                  <span
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px',
                      fontSize: '11px',
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
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
