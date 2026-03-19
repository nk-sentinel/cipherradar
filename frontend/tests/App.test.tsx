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

  it('shows SSO buttons on the login page', async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText('Sign in with GitHub SSO')).toBeInTheDocument();
    });
    expect(screen.getByText('Sign in with SAML / OIDC')).toBeInTheDocument();
  });
});
