import { useState, type FormEvent } from 'react';
import { Link, useSearch } from '@tanstack/react-router';

export function ResetPassword(): React.ReactElement {
  const search = useSearch({ strict: false }) as { token?: string };
  const token = search.token ?? '';

  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: FormEvent): Promise<void> => {
    e.preventDefault();
    setError(null);

    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setLoading(true);

    try {
      const response = await fetch('/api/v1/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, newPassword: password }),
      });

      if (!response.ok) {
        throw new Error('Reset failed');
      }

      setSuccess(true);
    } catch {
      setError('Failed to reset password. The link may be expired.');
    } finally {
      setLoading(false);
    }
  };

  if (!token) {
    return (
      <div className="login-page">
        <div className="login-card">
          <div className="login-title">CipherRadar</div>
          <div className="login-sub">Invalid Reset Link</div>
          <p style={{ fontSize: '12px', color: 'var(--text-2)', marginBottom: '12px' }}>
            This password reset link is invalid or missing the token.
          </p>
          <Link
            to="/login"
            style={{
              color: 'var(--accent)',
              fontSize: '12px',
              textDecoration: 'none',
            }}
          >
            Back to Sign In
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-title">CipherRadar</div>
        <div className="login-sub">Set new password</div>

        {success ? (
          <div data-testid="reset-success">
            <div
              style={{
                padding: '12px 16px',
                borderRadius: 'var(--radius)',
                marginBottom: '16px',
                fontSize: '12px',
                background: 'var(--badge-ok-bg)',
                color: 'var(--badge-ok-fg)',
                border: '1px solid var(--badge-ok-bd)',
              }}
            >
              Password reset successfully. You can now sign in with your new password.
            </div>
            <Link
              to="/login"
              style={{
                color: 'var(--accent)',
                fontSize: '12px',
                textDecoration: 'none',
              }}
            >
              Go to Sign In
            </Link>
          </div>
        ) : (
          <form onSubmit={(e) => void handleSubmit(e)}>
            {error && (
              <div
                role="alert"
                style={{
                  padding: '8px 12px',
                  borderRadius: 'var(--radius)',
                  marginBottom: '12px',
                  fontSize: '11px',
                  background: 'var(--badge-crit-bg)',
                  color: 'var(--badge-crit-fg)',
                  border: '1px solid var(--badge-crit-bd)',
                }}
              >
                {error}
              </div>
            )}

            <div className="field">
              <label className="field-label" htmlFor="reset-password">
                New Password
              </label>
              <input
                id="reset-password"
                className="input"
                type="password"
                placeholder="Min 8 characters"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={8}
              />
            </div>

            <div className="field">
              <label className="field-label" htmlFor="reset-confirm">
                Confirm New Password
              </label>
              <input
                id="reset-confirm"
                className="input"
                type="password"
                placeholder="Confirm new password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
              />
            </div>

            <button
              type="submit"
              className="login-btn"
              disabled={loading}
            >
              {loading ? 'Resetting...' : 'Reset Password'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
