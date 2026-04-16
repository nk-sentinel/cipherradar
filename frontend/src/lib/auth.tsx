import {
  createContext,
  useContext,
  useState,
  useCallback,
  useMemo,
  type ReactNode,
} from 'react';
import type { Role } from './roles';

export interface User {
  name: string;
  email: string;
  role: Role;
  initials: string;
}

interface AuthContextValue {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/**
 * Restore session atomically from sessionStorage.
 * Returns both token and user so they are always in sync.
 */
function restoreSession(): { token: string | null; user: User | null } {
  const storedToken = sessionStorage.getItem('cipherradar-token');
  const storedUser = sessionStorage.getItem('cipherradar-user');
  if (storedToken && storedUser) {
    try {
      return { token: storedToken, user: JSON.parse(storedUser) as User };
    } catch {
      return { token: null, user: null };
    }
  }
  return { token: null, user: null };
}

export function AuthProvider({ children }: { children: ReactNode }): React.ReactElement {
  // Restore both token and user atomically — no race between separate useState calls
  const [session, setSession] = useState(restoreSession);

  const login = useCallback(async (email: string, _password: string): Promise<void> => {
    const response = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: _password }),
      credentials: 'include', // receive httpOnly refresh cookie
    });

    if (!response.ok) {
      throw new Error('Login failed');
    }

    const data = (await response.json()) as {
      accessToken?: string;
      access_token?: string;
      token?: string;
      user?: User;
    };

    // Support camelCase (accessToken), legacy snake_case (access_token), and old { token } shapes
    const accessToken = data.accessToken ?? data.access_token ?? data.token ?? '';
    if (!accessToken) {
      throw new Error('No token in response');
    }

    // If backend provides user object use it, otherwise derive from email + token
    let userInfo: User;
    if (data.user) {
      userInfo = data.user;
    } else {
      // Derive user info from the JWT claims or email
      const namePart = email.split('@')[0] ?? 'User';
      const name = namePart
        .replace(/[-_.]/g, ' ')
        .replace(/\b\w/g, (c) => c.toUpperCase());
      const initials = name
        .split(' ')
        .map((w) => w[0])
        .join('')
        .toUpperCase()
        .slice(0, 2);

      // Decode role from JWT payload (base64url-encoded middle segment)
      let role: Role = 'developer';
      try {
        const payload = JSON.parse(atob(accessToken.split('.')[1] ?? ''));
        const rawRole = (payload.role ?? 'developer') as string;
        // Backend uses underscores (org_admin), frontend uses hyphens (org-admin)
        role = rawRole.replace(/_/g, '-') as Role;
      } catch {
        // ignore decode errors
      }

      userInfo = { name, email, role, initials };
    }

    sessionStorage.setItem('cipherradar-token', accessToken);
    sessionStorage.setItem('cipherradar-user', JSON.stringify(userInfo));
    setSession({ token: accessToken, user: userInfo });
  }, []);

  const logout = useCallback((): void => {
    // Clear httpOnly refresh cookie via backend
    fetch('/api/v1/auth/logout', { method: 'POST', credentials: 'include' }).catch(() => {});
    sessionStorage.removeItem('cipherradar-token');
    sessionStorage.removeItem('cipherradar-user');
    setSession({ token: null, user: null });
  }, []);

  const value = useMemo(
    (): AuthContextValue => ({
      user: session.user,
      token: session.token,
      isAuthenticated: !!session.token && !!session.user,
      login,
      logout,
    }),
    [session, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
