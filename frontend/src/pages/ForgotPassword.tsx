import { useState, type FormEvent } from 'react';
import { Link } from '@tanstack/react-router';

export function ForgotPassword(): React.ReactElement {
  const [email, setEmail] = useState('');
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent): Promise<void> => {
    e.preventDefault();
    setLoading(true);

    try {
      await fetch('/api/v1/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
    } catch {
      // Intentionally swallow errors — same success message regardless
    } finally {
      setLoading(false);
      setSubmitted(true);
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-title">CipherRadar</div>
        <div className="login-sub">Reset your password</div>

        {submitted ? (
          <div data-testid="forgot-success">
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
              If an account exists with that email, a reset link has been sent.
            </div>
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
        ) : (
          <form onSubmit={(e) => void handleSubmit(e)}>
            <div className="field">
              <label className="field-label" htmlFor="forgot-email">
                Email
              </label>
              <input
                id="forgot-email"
                className="input"
                type="email"
                placeholder="you@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>

            <button
              type="submit"
              className="login-btn"
              disabled={loading}
            >
              {loading ? 'Sending...' : 'Send Reset Link'}
            </button>

            <div style={{ marginTop: '12px', textAlign: 'center' }}>
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
          </form>
        )}
      </div>
    </div>
  );
}
