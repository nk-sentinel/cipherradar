import { describe, it, expect, beforeAll, afterAll, afterEach, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { setupServer } from 'msw/node';
import { http, HttpResponse } from 'msw';
import { ForgotPassword } from '../../src/pages/ForgotPassword.tsx';
import {
  createRouter,
  createRootRoute,
  createRoute,
  RouterProvider,
  createMemoryHistory,
} from '@tanstack/react-router';

const server = setupServer(
  http.post('/api/v1/auth/forgot-password', async () => {
    return HttpResponse.json({
      message: 'If the email is registered, a reset link has been sent',
    });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderWithRouter() {
  const rootRoute = createRootRoute();
  const forgotRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/forgot-password',
    component: ForgotPassword,
  });
  const loginRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: '/login',
    component: () => <div data-testid="login-page">Login Page</div>,
  });

  const routeTree = rootRoute.addChildren([forgotRoute, loginRoute]);

  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: ['/forgot-password'] }),
  });

  return render(<RouterProvider router={router} />);
}

describe('ForgotPassword page', () => {
  beforeEach(() => {
    try { sessionStorage.clear(); } catch { /* ignore */ }
  });

  it('renders the forgot password form', () => {
    renderWithRouter();
    expect(screen.getByText('Reset your password')).toBeInTheDocument();
    expect(screen.getByLabelText('Email')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /send reset link/i })).toBeInTheDocument();
  });

  it('shows back to sign in link', () => {
    renderWithRouter();
    expect(screen.getByText('Back to Sign In')).toBeInTheDocument();
  });

  it('submits form and shows success message', async () => {
    renderWithRouter();

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'test@example.com' },
    });

    fireEvent.click(screen.getByRole('button', { name: /send reset link/i }));

    await waitFor(() => {
      expect(screen.getByTestId('forgot-success')).toBeInTheDocument();
    });

    expect(
      screen.getByText(/if an account exists with that email, a reset link has been sent/i),
    ).toBeInTheDocument();
  });

  it('shows same success message even on server error', async () => {
    server.use(
      http.post('/api/v1/auth/forgot-password', () => {
        return new HttpResponse(
          JSON.stringify({ detail: 'Server error' }),
          { status: 500 },
        );
      }),
    );

    renderWithRouter();

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'nonexistent@example.com' },
    });

    fireEvent.click(screen.getByRole('button', { name: /send reset link/i }));

    await waitFor(() => {
      expect(screen.getByTestId('forgot-success')).toBeInTheDocument();
    });

    // Should STILL show the generic message (no leak of account existence)
    expect(
      screen.getByText(/if an account exists with that email, a reset link has been sent/i),
    ).toBeInTheDocument();
  });

  it('disables button while loading', async () => {
    renderWithRouter();

    fireEvent.change(screen.getByLabelText('Email'), {
      target: { value: 'test@example.com' },
    });

    const btn = screen.getByRole('button', { name: /send reset link/i });
    fireEvent.click(btn);

    // Button text changes while loading
    expect(screen.getByRole('button', { name: /sending/i })).toBeDisabled();

    await waitFor(() => {
      expect(screen.getByTestId('forgot-success')).toBeInTheDocument();
    });
  });

  it('renders CipherRadar title', () => {
    renderWithRouter();
    expect(screen.getByText('CipherRadar')).toBeInTheDocument();
  });
});
