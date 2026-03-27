import { useState, type FormEvent } from 'react';
import { useNavigate, Link } from '@tanstack/react-router';
import { useAuth } from '@/lib/auth';

export function Login(): React.ReactElement {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: FormEvent): Promise<void> => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await login(email, password);
      void navigate({ to: '/' });
    } catch {
      setError('Invalid credentials');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <form className="login-card" onSubmit={(e) => void handleSubmit(e)}>
        <div className="login-title">CipherRadar</div>
        <div className="login-sub">
          Cryptographic Asset Intelligence Platform
        </div>

        {error && (
          <div
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
          <label className="field-label" htmlFor="login-email">
            Email
          </label>
          <input
            id="login-email"
            className="input"
            type="email"
            placeholder="you@company.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>

        <div className="field">
          <label className="field-label" htmlFor="login-password">
            Password
          </label>
          <input
            id="login-password"
            className="input"
            type="password"
            placeholder="Enter password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>

        <div style={{ textAlign: 'right', marginBottom: '8px' }}>
          <Link
            to="/forgot-password"
            style={{
              color: 'var(--accent)',
              fontSize: '11px',
              textDecoration: 'none',
            }}
            data-testid="forgot-password-link"
          >
            Forgot Password?
          </Link>
        </div>

        <button
          type="submit"
          className="login-btn"
          disabled={loading}
        >
          {loading ? 'Signing in...' : 'Sign In'}
        </button>
      </form>
    </div>
  );
}
