import { useState, type FormEvent } from 'react';
import { useChangePassword } from '@/api/hooks/usePassword.ts';

interface PasswordChangeFormProps {
  authSource: string;
}

export function PasswordChangeForm({ authSource }: PasswordChangeFormProps): React.ReactElement {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [validationError, setValidationError] = useState<string | null>(null);
  const changePassword = useChangePassword();

  if (authSource !== 'local') {
    return (
      <div className="card">
        <div className="card-title">Password</div>
        <div
          data-testid="managed-by-idp"
          style={{
            padding: '12px 16px',
            borderRadius: 'var(--radius)',
            background: 'var(--accent-dim)',
            color: 'var(--text-2)',
            fontSize: '12px',
            border: '1px solid var(--border)',
          }}
        >
          Password is managed by <strong>{authSource}</strong>. To change your password, visit your identity provider.
        </div>
      </div>
    );
  }

  const handleSubmit = (e: FormEvent): void => {
    e.preventDefault();
    setValidationError(null);

    if (newPassword.length < 8) {
      setValidationError('Password must be at least 8 characters');
      return;
    }
    if (newPassword !== confirmPassword) {
      setValidationError('Passwords do not match');
      return;
    }
    if (newPassword === currentPassword) {
      setValidationError('New password must be different from current password');
      return;
    }

    changePassword.mutate(
      { currentPassword, newPassword },
      {
        onSuccess: () => {
          setCurrentPassword('');
          setNewPassword('');
          setConfirmPassword('');
        },
      },
    );
  };

  return (
    <div className="card">
      <div className="card-title">Change Password</div>
      <form onSubmit={handleSubmit}>
        <div className="g2" style={{ marginBottom: '8px' }}>
          <div className="field">
            <label className="field-label" htmlFor="current-password">
              Current Password
            </label>
            <input
              id="current-password"
              className="input"
              type="password"
              placeholder="Enter current password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              required
            />
          </div>
          <div className="field">
            <label className="field-label" htmlFor="new-password">
              New Password
            </label>
            <input
              id="new-password"
              className="input"
              type="password"
              placeholder="Min 8 characters"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
              minLength={8}
            />
          </div>
          <div className="field">
            <label className="field-label" htmlFor="confirm-password">
              Confirm New Password
            </label>
            <input
              id="confirm-password"
              className="input"
              type="password"
              placeholder="Confirm new password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
            />
          </div>
        </div>

        {validationError && (
          <div
            role="alert"
            style={{
              padding: '6px 12px',
              borderRadius: 'var(--radius)',
              marginBottom: '8px',
              fontSize: '11px',
              background: 'var(--badge-crit-bg)',
              color: 'var(--badge-crit-fg)',
              border: '1px solid var(--badge-crit-bd)',
            }}
          >
            {validationError}
          </div>
        )}

        <button
          type="submit"
          className="btn btn-accent"
          disabled={changePassword.isPending || !currentPassword || !newPassword || !confirmPassword}
        >
          {changePassword.isPending ? 'Changing...' : 'Change Password'}
        </button>
      </form>
    </div>
  );
}
