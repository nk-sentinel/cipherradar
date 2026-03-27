import { describe, it, expect, vi, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { UserCreateModal } from '../../src/components/admin/UserCreateModal.tsx';
import { AuthProvider } from '../../src/lib/auth.tsx';

const server = setupServer(
  http.post('/api/v1/admin/users/invite', async () => {
    return HttpResponse.json({ success: true });
  }),
  http.post('/api/v1/admin/users', async () => {
    return HttpResponse.json({ success: true, id: 'u-new' });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function setMockUser(role: string) {
  const user = {
    name: 'Test User',
    email: 'test@example.com',
    role,
    initials: 'TU',
  };
  sessionStorage.setItem('cipherradar-token', 'mock-token');
  sessionStorage.setItem('cipherradar-user', JSON.stringify(user));
}

function renderWithProviders(onClose = vi.fn()) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <UserCreateModal onClose={onClose} />
      </AuthProvider>
    </QueryClientProvider>,
  );
}

describe('UserCreateModal', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* ignore */ }
  });

  it('renders modal with invite mode as default', () => {
    setMockUser('org-admin');
    renderWithProviders();
    expect(screen.getByTestId('user-create-modal')).toBeInTheDocument();
    expect(screen.getByTestId('mode-invite')).toBeInTheDocument();
    expect(screen.getByTestId('mode-direct')).toBeInTheDocument();
    // Email field should exist
    expect(screen.getByLabelText('Email')).toBeInTheDocument();
    // Name/password should NOT exist in invite mode
    expect(screen.queryByLabelText('Full Name')).not.toBeInTheDocument();
  });

  it('switches to direct add mode', () => {
    setMockUser('org-admin');
    renderWithProviders();

    fireEvent.click(screen.getByTestId('mode-direct'));

    expect(screen.getByLabelText('Full Name')).toBeInTheDocument();
    expect(screen.getByLabelText('Temporary Password')).toBeInTheDocument();
    expect(screen.getByTestId('force-change-notice')).toBeInTheDocument();
  });

  it('shows force-change notice in direct mode', () => {
    setMockUser('org-admin');
    renderWithProviders();

    fireEvent.click(screen.getByTestId('mode-direct'));

    expect(screen.getByTestId('force-change-notice')).toHaveTextContent(
      /required to change their password/i,
    );
  });

  it('shows all 7 roles for org-admin', () => {
    setMockUser('org-admin');
    renderWithProviders();

    const select = screen.getByLabelText('Role');
    const options = Array.from(select.querySelectorAll('option'));
    expect(options).toHaveLength(7);
  });

  it('shows capped roles for security-manager (no OA or SM)', () => {
    setMockUser('security-manager');
    renderWithProviders();

    const select = screen.getByLabelText('Role');
    const options = Array.from(select.querySelectorAll('option'));
    expect(options).toHaveLength(5);
    const values = options.map((o) => o.value);
    expect(values).not.toContain('org-admin');
    expect(values).not.toContain('security-manager');
    expect(values).toContain('developer');
  });

  it('submits invite and calls onClose', async () => {
    setMockUser('org-admin');
    const onClose = vi.fn();
    renderWithProviders(onClose);

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'new@example.com' },
    });

    fireEvent.click(screen.getByRole('button', { name: /send invite/i }));

    await waitFor(() => {
      expect(onClose).toHaveBeenCalled();
    });
  });

  it('submits direct add and calls onClose', async () => {
    setMockUser('org-admin');
    const onClose = vi.fn();
    renderWithProviders(onClose);

    fireEvent.click(screen.getByTestId('mode-direct'));

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'new@example.com' },
    });
    fireEvent.change(screen.getByLabelText('Full Name'), {
      target: { value: 'New Person' },
    });
    fireEvent.change(screen.getByLabelText('Temporary Password'), {
      target: { value: 'temppass123' },
    });

    fireEvent.click(screen.getByRole('button', { name: /add user/i }));

    await waitFor(() => {
      expect(onClose).toHaveBeenCalled();
    });
  });

  it('cancel button calls onClose', () => {
    setMockUser('org-admin');
    const onClose = vi.fn();
    renderWithProviders(onClose);

    fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
    expect(onClose).toHaveBeenCalled();
  });
});
