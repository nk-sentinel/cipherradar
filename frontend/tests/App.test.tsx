import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { App } from '../src/App';

describe('App', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* jsdom may not support */ }
    try { localStorage.clear(); } catch { /* jsdom may not support */ }
  });

  it('renders the login page when not authenticated', async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText('CipherRadar')).toBeInTheDocument();
    });
    expect(screen.getByText('Sign In')).toBeInTheDocument();
  });

  it('does not show SSO buttons on the login page (D8: removed)', async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText('Sign In')).toBeInTheDocument();
    });
    expect(screen.queryByText('Sign in with GitHub SSO')).not.toBeInTheDocument();
    expect(screen.queryByText('Sign in with SAML / OIDC')).not.toBeInTheDocument();
  });
});
