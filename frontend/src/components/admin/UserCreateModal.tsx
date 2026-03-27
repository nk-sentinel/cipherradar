import { useState, type FormEvent } from 'react';
import { useAuth } from '@/lib/auth.tsx';
import { ROLE_LABELS, type Role } from '@/lib/roles.ts';
import {
  useInviteUser,
  useDirectAddUser,
} from '@/api/hooks/useUserManagement.ts';

interface UserCreateModalProps {
  onClose: () => void;
}

type CreateMode = 'invite' | 'direct';

/**
 * Role assignment caps per D10.
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

export function UserCreateModal({ onClose }: UserCreateModalProps): React.ReactElement {
  const { user } = useAuth();
  const inviteUser = useInviteUser();
  const directAddUser = useDirectAddUser();

  const [mode, setMode] = useState<CreateMode>('invite');
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [tempPassword, setTempPassword] = useState('');
  const [role, setRole] = useState<Role>('developer');
  const [groupIds] = useState<string[]>([]);

  const allowedRoles = user ? ASSIGNABLE_ROLES[user.role] ?? [] : [];

  const handleSubmit = (e: FormEvent): void => {
    e.preventDefault();

    if (mode === 'invite') {
      inviteUser.mutate(
        { email, role },
        { onSuccess: () => onClose() },
      );
    } else {
      directAddUser.mutate(
        { email, name, tempPassword, role, groupIds },
        { onSuccess: () => onClose() },
      );
    }
  };

  const isPending = mode === 'invite' ? inviteUser.isPending : directAddUser.isPending;

  return (
    <div className="card" data-testid="user-create-modal">
      <div className="card-title">Add New User</div>

      {/* Mode toggle */}
      <div
        style={{
          display: 'flex',
          gap: '4px',
          marginBottom: '16px',
          background: 'var(--surface-2)',
          borderRadius: 'var(--radius)',
          padding: '3px',
          border: '1px solid var(--border)',
        }}
      >
        <button
          type="button"
          className={mode === 'invite' ? 'btn btn-accent' : 'btn btn-outline'}
          onClick={() => setMode('invite')}
          data-testid="mode-invite"
          style={{ flex: 1, fontSize: '11px' }}
        >
          Send Invite
        </button>
        <button
          type="button"
          className={mode === 'direct' ? 'btn btn-accent' : 'btn btn-outline'}
          onClick={() => setMode('direct')}
          data-testid="mode-direct"
          style={{ flex: 1, fontSize: '11px' }}
        >
          Add Directly
        </button>
      </div>

      <form onSubmit={handleSubmit}>
        <div className="g2" style={{ marginBottom: '8px' }}>
          <div className="field">
            <label className="field-label" htmlFor="user-email">
              Email
            </label>
            <input
              id="user-email"
              className="input"
              type="email"
              placeholder="user@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>

          {mode === 'direct' && (
            <>
              <div className="field">
                <label className="field-label" htmlFor="user-name">
                  Full Name
                </label>
                <input
                  id="user-name"
                  className="input"
                  type="text"
                  placeholder="Jane Doe"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="user-temp-password">
                  Temporary Password
                </label>
                <input
                  id="user-temp-password"
                  className="input"
                  type="password"
                  placeholder="Min 8 characters"
                  value={tempPassword}
                  onChange={(e) => setTempPassword(e.target.value)}
                  required
                  minLength={8}
                />
              </div>
            </>
          )}

          <div className="field">
            <label className="field-label" htmlFor="user-role">
              Role
            </label>
            <select
              id="user-role"
              className="input"
              value={role}
              onChange={(e) => setRole(e.target.value as Role)}
            >
              {allowedRoles.map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABELS[r]}
                </option>
              ))}
            </select>
          </div>
        </div>

        {mode === 'direct' && (
          <div
            style={{
              padding: '8px 12px',
              borderRadius: 'var(--radius)',
              marginBottom: '12px',
              fontSize: '11px',
              background: 'var(--accent-dim)',
              color: 'var(--text-2)',
              border: '1px solid var(--border)',
            }}
            data-testid="force-change-notice"
          >
            User will be required to change their password on first login.
          </div>
        )}

        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            type="submit"
            className="btn btn-accent"
            disabled={isPending || !email.trim()}
          >
            {isPending
              ? 'Saving...'
              : mode === 'invite'
                ? 'Send Invite'
                : 'Add User'}
          </button>
          <button type="button" className="btn btn-outline" onClick={onClose}>
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}
