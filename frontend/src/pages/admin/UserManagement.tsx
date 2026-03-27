import { useState, useMemo } from 'react';
import { RequireRole } from '@/components/guards/RequireRole.tsx';
import { useAuth } from '@/lib/auth.tsx';
import { ROLE_LABELS, type Role } from '@/lib/roles.ts';
import { Pagination } from '@/components/ui/Pagination.tsx';
import { UserCreateModal } from '@/components/admin/UserCreateModal.tsx';
import { UserDetailDrawer } from '@/components/admin/UserDetailDrawer.tsx';
import {
  useUsers,
  useChangeRole,
  useDisableUser,
  useEnableUser,
  useDeleteUser,
  type ManagedUser,
} from '@/api/hooks/useUserManagement.ts';

export function UserManagement(): React.ReactElement {
  return (
    <RequireRole roles={['org-admin', 'security-manager']}>
      <UserManagementContent />
    </RequireRole>
  );
}

/**
 * Roles that the current user can assign via the inline dropdown (D10).
 */
const ASSIGNABLE_ROLES: Record<Role, Role[]> = {
  'org-admin': [
    'org-admin',
    'security-manager',
    'security-engineer',
    'team-manager',
    'compliance-auditor',
    'developer',
    'guest',
  ],
  'security-manager': [
    'security-engineer',
    'team-manager',
    'compliance-auditor',
    'developer',
    'guest',
  ],
  'security-engineer': [],
  'team-manager': [],
  'compliance-auditor': [],
  developer: [],
  guest: [],
};

/**
 * Get stale indicator color based on last active string.
 * Orange >30d, red >90d.
 */
function getStaleColor(lastActive: string): string | undefined {
  const daysMatch = lastActive.match(/(\d+)\s*days?\s*ago/i);
  if (daysMatch) {
    const days = parseInt(daysMatch[1] ?? '0', 10);
    if (days > 90) return 'var(--red)';
    if (days > 30) return 'var(--yellow)';
  }
  if (lastActive === 'Never') return 'var(--red)';
  return undefined;
}

function UserManagementContent(): React.ReactElement {
  const { user: currentUser } = useAuth();
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(25);
  const [search, setSearch] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [selectedUser, setSelectedUser] = useState<ManagedUser | null>(null);

  const { data, isLoading, error } = useUsers(page, perPage, search);
  const changeRole = useChangeRole();
  const disableUser = useDisableUser();
  const enableUser = useEnableUser();
  const deleteUser = useDeleteUser();

  const allowedRoles = useMemo(
    () => (currentUser ? ASSIGNABLE_ROLES[currentUser.role] ?? [] : []),
    [currentUser],
  );

  const canEditRole = currentUser?.role === 'org-admin';

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

  const users = data.items;
  const total = data.total;

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
        <button
          className="btn btn-accent"
          onClick={() => setShowCreate(true)}
          data-testid="add-user-btn"
        >
          + Add User
        </button>
      </div>

      {/* Search */}
      <div style={{ marginBottom: '16px' }}>
        <input
          className="input"
          type="text"
          placeholder="Search by name or email..."
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(1);
          }}
          data-testid="user-search"
          style={{ maxWidth: '320px' }}
        />
      </div>

      {/* Create modal */}
      {showCreate && (
        <div style={{ marginBottom: '16px' }}>
          <UserCreateModal onClose={() => setShowCreate(false)} />
        </div>
      )}

      {/* User table */}
      <div className="card">
        <div className="card-title">
          Users ({total})
        </div>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Email</th>
              <th>Role</th>
              <th>Last Active</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr
                key={u.id}
                style={{ cursor: 'pointer' }}
                onClick={() => setSelectedUser(u)}
                data-testid={`user-row-${u.id}`}
              >
                <td>
                  <strong>{u.name}</strong>
                </td>
                <td style={{ color: 'var(--text-2)' }}>{u.email}</td>
                <td>
                  {canEditRole ? (
                    <select
                      className="input"
                      value={u.role}
                      onClick={(e) => e.stopPropagation()}
                      onChange={(e) => {
                        e.stopPropagation();
                        changeRole.mutate({
                          userId: u.id,
                          role: e.target.value as Role,
                        });
                      }}
                      data-testid={`role-select-${u.id}`}
                      style={{
                        fontSize: '10px',
                        padding: '2px 6px',
                        width: 'auto',
                        minWidth: '120px',
                      }}
                    >
                      {allowedRoles.map((r) => (
                        <option key={r} value={r}>
                          {ROLE_LABELS[r]}
                        </option>
                      ))}
                    </select>
                  ) : (
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
                      {ROLE_LABELS[u.role]}
                    </span>
                  )}
                </td>
                <td
                  style={{
                    color: getStaleColor(u.lastActive) ?? 'var(--text-3)',
                    fontSize: '11px',
                    fontWeight: getStaleColor(u.lastActive) ? 600 : 400,
                  }}
                  data-testid={`last-active-${u.id}`}
                >
                  {getStaleColor(u.lastActive) && (
                    <span
                      style={{
                        display: 'inline-block',
                        width: '6px',
                        height: '6px',
                        borderRadius: '50%',
                        background: getStaleColor(u.lastActive),
                        marginRight: '4px',
                      }}
                      data-testid={`stale-indicator-${u.id}`}
                    />
                  )}
                  {u.lastActive}
                </td>
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
                          u.status === 'active'
                            ? 'var(--green)'
                            : u.status === 'invited'
                              ? 'var(--yellow)'
                              : 'var(--red)',
                      }}
                    />
                    {u.status.charAt(0).toUpperCase() + u.status.slice(1)}
                  </span>
                </td>
                <td>
                  <div
                    style={{ display: 'flex', gap: '4px' }}
                    onClick={(e) => e.stopPropagation()}
                  >
                    {u.status === 'active' && (
                      <button
                        className="btn btn-outline"
                        style={{ fontSize: '10px', padding: '2px 8px', color: 'var(--yellow)' }}
                        data-testid={`disable-btn-${u.id}`}
                        disabled={disableUser.isPending}
                        onClick={() => disableUser.mutate(u.id)}
                      >
                        Disable
                      </button>
                    )}
                    {u.status === 'disabled' && (
                      <>
                        <button
                          className="btn btn-outline"
                          style={{ fontSize: '10px', padding: '2px 8px', color: 'var(--green)' }}
                          data-testid={`enable-btn-${u.id}`}
                          disabled={enableUser.isPending}
                          onClick={() => enableUser.mutate(u.id)}
                        >
                          Enable
                        </button>
                        <button
                          className="btn btn-outline"
                          style={{ fontSize: '10px', padding: '2px 8px', color: 'var(--red)' }}
                          data-testid={`delete-btn-${u.id}`}
                          disabled={deleteUser.isPending}
                          onClick={() => deleteUser.mutate(u.id)}
                        >
                          Delete
                        </button>
                      </>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {/* Pagination */}
        <div style={{ marginTop: '12px' }}>
          <Pagination
            page={page}
            perPage={perPage}
            total={total}
            onPageChange={setPage}
            onPerPageChange={(newPerPage) => {
              setPerPage(newPerPage);
              setPage(1);
            }}
          />
        </div>
      </div>

      {/* Detail drawer */}
      {selectedUser && (
        <UserDetailDrawer
          user={selectedUser}
          onClose={() => setSelectedUser(null)}
        />
      )}
    </div>
  );
}
