import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { PasswordChangeForm } from '../../src/components/profile/PasswordChangeForm.tsx';

const server = setupServer(
  http.put('/api/v1/auth/password', async () => {
    return HttpResponse.json({ success: true });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderWithProviders(authSource = 'local') {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <PasswordChangeForm authSource={authSource} />
    </QueryClientProvider>,
  );
}

describe('PasswordChangeForm', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* ignore */ }
  });

  it('renders password form for local auth source', () => {
    renderWithProviders('local');
    expect(screen.getByText('Change Password')).toBeInTheDocument();
    expect(screen.getByLabelText('Current Password')).toBeInTheDocument();
    expect(screen.getByLabelText('New Password')).toBeInTheDocument();
    expect(screen.getByLabelText('Confirm New Password')).toBeInTheDocument();
  });

  it('shows managed-by-idp message for SSO users', () => {
    renderWithProviders('okta');
    expect(screen.getByTestId('managed-by-idp')).toBeInTheDocument();
    expect(screen.getByText(/managed by/i)).toBeInTheDocument();
    expect(screen.getByText('okta')).toBeInTheDocument();
    expect(screen.queryByLabelText('Current Password')).not.toBeInTheDocument();
  });

  it('shows managed-by-idp for Azure AD', () => {
    renderWithProviders('azure-ad');
    expect(screen.getByTestId('managed-by-idp')).toBeInTheDocument();
    expect(screen.getByText('azure-ad')).toBeInTheDocument();
  });

  it('validates minimum password length', async () => {
    renderWithProviders('local');

    fireEvent.change(screen.getByLabelText('Current Password'), {
      target: { value: 'oldpass123' },
    });
    fireEvent.change(screen.getByLabelText('New Password'), {
      target: { value: 'short' },
    });
    fireEvent.change(screen.getByLabelText('Confirm New Password'), {
      target: { value: 'short' },
    });

    fireEvent.submit(screen.getByRole('button', { name: /change password/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Password must be at least 8 characters');
    });
  });

  it('validates passwords match', async () => {
    renderWithProviders('local');

    fireEvent.change(screen.getByLabelText('Current Password'), {
      target: { value: 'oldpass123' },
    });
    fireEvent.change(screen.getByLabelText('New Password'), {
      target: { value: 'newpass1234' },
    });
    fireEvent.change(screen.getByLabelText('Confirm New Password'), {
      target: { value: 'different123' },
    });

    fireEvent.submit(screen.getByRole('button', { name: /change password/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Passwords do not match');
    });
  });

  it('validates new password differs from current', async () => {
    renderWithProviders('local');

    fireEvent.change(screen.getByLabelText('Current Password'), {
      target: { value: 'samepass123' },
    });
    fireEvent.change(screen.getByLabelText('New Password'), {
      target: { value: 'samepass123' },
    });
    fireEvent.change(screen.getByLabelText('Confirm New Password'), {
      target: { value: 'samepass123' },
    });

    fireEvent.submit(screen.getByRole('button', { name: /change password/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('New password must be different from current password');
    });
  });

  it('submits valid password change', async () => {
    renderWithProviders('local');

    fireEvent.change(screen.getByLabelText('Current Password'), {
      target: { value: 'oldpass123' },
    });
    fireEvent.change(screen.getByLabelText('New Password'), {
      target: { value: 'newpass1234' },
    });
    fireEvent.change(screen.getByLabelText('Confirm New Password'), {
      target: { value: 'newpass1234' },
    });

    fireEvent.submit(screen.getByRole('button', { name: /change password/i }));

    // After successful submission, fields should be cleared
    await waitFor(() => {
      expect((screen.getByLabelText('Current Password') as HTMLInputElement).value).toBe('');
    });
  });

  it('disables submit button when fields are empty', () => {
    renderWithProviders('local');
    expect(screen.getByRole('button', { name: /change password/i })).toBeDisabled();
  });
});
