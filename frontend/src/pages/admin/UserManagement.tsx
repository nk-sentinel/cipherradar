import { useState, useMemo } from 'react';
import { RequireRole } from '@/components/guards/RequireRole.tsx';
import { useAuth } from '@/lib/auth.tsx';
import { ROLE_LABELS, type Role } from '@/lib/roles.ts';
import { Pagination } from '@/components/ui/Pagination.tsx';
import { UserCreateModal } from '@/components/admin/UserCreateModal.tsx';
import { UserDetailDrawer } from '@/components/admin/UserDetailDrawer.tsx';
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '@/api/client.ts';
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
    <RequireRole
      roles={['org-admin', 'security-manager']}
      fallback={
        <div className="card">
          <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>
            Access denied. You do not have permission to manage users. Contact your admin.
          </p>
        </div>
      }
    >
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

  // C5: Delete confirmation state
  const [deleteTarget, setDeleteTarget] = useState<ManagedUser | null>(null);
  const [deleteConfirmText, setDeleteConfirmText] = useState('');

  // H8: Role change confirmation state
  const [roleChangeTarget, setRoleChangeTarget] = useState<{ user: ManagedUser; newRole: Role } | null>(null);

  // H9: Last OA error
  const [lastOAError, setLastOAError] = useState<string | null>(null);

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

  // H9: Count org admins across ALL pages (not just current page) for last-OA check
  const { data: oaCountData } = useQuery({
    queryKey: ['org-admin-count'],
    queryFn: async () => {
      const res = await apiClient<{ items: unknown[]; total: number } | unknown[]>('/admin/users?role=org_admin&per_page=1');
      return Array.isArray(res) ? res.length : (res?.total ?? 0);
    },
  });
  const orgAdminCount = oaCountData ?? 0;

  // H9: Check if user is last org admin before disable/demote
  const isLastOrgAdmin = (targetUser: ManagedUser): boolean => {
    return targetUser.role === 'org-admin' && orgAdminCount <= 1;
  };

  // H8: Handle role change with confirmation
  const handleRoleChangeRequest = (targetUser: ManagedUser, newRole: Role) => {
    if (newRole === targetUser.role) return;
    // H9: Prevent demoting the last OA
    if (targetUser.role === 'org-admin' && newRole !== 'org-admin' && isLastOrgAdmin(targetUser)) {
      setLastOAError('Cannot demote the last Org Admin. Promote another user to Org Admin first.');
      return;
    }
    setRoleChangeTarget({ user: targetUser, newRole });
  };

  const confirmRoleChange = () => {
    if (!roleChangeTarget) return;
    changeRole.mutate({
      userId: roleChangeTarget.user.id,
      role: roleChangeTarget.newRole,
    });
    setRoleChangeTarget(null);
  };

  // H9: Handle disable with last-OA check
  const handleDisableRequest = (targetUser: ManagedUser) => {
    if (isLastOrgAdmin(targetUser)) {
      setLastOAError('Cannot disable the last Org Admin. Promote another user to Org Admin first.');
      return;
    }
    disableUser.mutate(targetUser.id);
  };

  // C5: Handle delete with confirmation dialog
  const handleDeleteRequest = (targetUser: ManagedUser) => {
    setDeleteTarget(targetUser);
    setDeleteConfirmText('');
  };

  const confirmDelete = () => {
    if (!deleteTarget) return;
    deleteUser.mutate(deleteTarget.id);
    setDeleteTarget(null);
    setDeleteConfirmText('');
  };

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
              <th scope="col">Name</th>
              <th scope="col">Email</th>
              <th scope="col">Role</th>
              <th scope="col">Last Active</th>
              <th scope="col">Status</th>
              <th scope="col">Actions</th>
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
                        handleRoleChangeRequest(u, e.target.value as Role);
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
                        onClick={() => handleDisableRequest(u)}
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
                          onClick={() => handleDeleteRequest(u)}
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

      {/* C5: Delete confirmation dialog */}
      {deleteTarget && (
        <div
          className="modal-overlay"
          data-testid="delete-confirm-modal"
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}
          onClick={(e) => { if (e.target === e.currentTarget) setDeleteTarget(null); }}
        >
          <div className="modal card" style={{ maxWidth: '400px', width: '100%' }}>
            <h3 style={{ fontSize: '14px', fontWeight: 700, marginBottom: '12px' }}>
              Confirm User Deletion
            </h3>
            <p style={{ fontSize: '12px', color: 'var(--text-2)', marginBottom: '12px' }}>
              Type &quot;<strong>{deleteTarget.email}</strong>&quot; to confirm deletion:
            </p>
            <input
              className="input"
              value={deleteConfirmText}
              onChange={(e) => setDeleteConfirmText(e.target.value)}
              placeholder={deleteTarget.email}
              data-testid="delete-confirm-input"
              style={{ marginBottom: '12px' }}
            />
            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
              <button className="btn btn-outline" onClick={() => setDeleteTarget(null)}>
                Cancel
              </button>
              <button
                className="btn btn-accent"
                style={{ background: 'var(--red)', borderColor: 'var(--red)' }}
                disabled={deleteConfirmText !== deleteTarget.email}
                onClick={confirmDelete}
                data-testid="delete-confirm-btn"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {/* H8: Role change confirmation dialog */}
      {roleChangeTarget && (
        <div
          className="modal-overlay"
          data-testid="role-change-confirm-modal"
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}
          onClick={(e) => { if (e.target === e.currentTarget) setRoleChangeTarget(null); }}
        >
          <div className="modal card" style={{ maxWidth: '400px', width: '100%' }}>
            <h3 style={{ fontSize: '14px', fontWeight: 700, marginBottom: '12px' }}>
              Confirm Role Change
            </h3>
            <p style={{ fontSize: '12px', color: 'var(--text-2)', marginBottom: '12px' }}>
              Change <strong>{roleChangeTarget.user.name}</strong>&apos;s role from{' '}
              <strong>{ROLE_LABELS[roleChangeTarget.user.role]}</strong> to{' '}
              <strong>{ROLE_LABELS[roleChangeTarget.newRole]}</strong>?
            </p>
            <p style={{ fontSize: '11px', color: 'var(--orange)', marginBottom: '12px' }}>
              This may revoke API keys with scopes exceeding the new role.
            </p>
            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
              <button className="btn btn-outline" onClick={() => setRoleChangeTarget(null)}>
                Cancel
              </button>
              <button
                className="btn btn-accent"
                onClick={confirmRoleChange}
                data-testid="role-change-confirm-btn"
              >
                Confirm
              </button>
            </div>
          </div>
        </div>
      )}

      {/* H9: Last OA error dialog */}
      {lastOAError && (
        <div
          className="modal-overlay"
          data-testid="last-oa-error-modal"
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}
          onClick={(e) => { if (e.target === e.currentTarget) setLastOAError(null); }}
        >
          <div className="modal card" style={{ maxWidth: '400px', width: '100%' }}>
            <h3 style={{ fontSize: '14px', fontWeight: 700, marginBottom: '12px', color: 'var(--red)' }}>
              Action Blocked
            </h3>
            <p style={{ fontSize: '12px', color: 'var(--text-2)', marginBottom: '12px' }}>
              {lastOAError}
            </p>
            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
              <button className="btn btn-accent" onClick={() => setLastOAError(null)}>
                OK
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
