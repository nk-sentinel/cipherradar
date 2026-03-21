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

// Store JWT in memory (not localStorage) for security
let memoryToken: string | null = null;

export function AuthProvider({ children }: { children: ReactNode }): React.ReactElement {
  const [user, setUser] = useState<User | null>(() => {
    // Restore session from sessionStorage (tab-scoped)
    const stored = sessionStorage.getItem('cipherradar-token');
    const storedUser = sessionStorage.getItem('cipherradar-user');
    if (stored && storedUser) {
      memoryToken = stored;
      try {
        return JSON.parse(storedUser) as User;
      } catch {
        return null;
      }
    }
    return null;
  });

  const [token, setToken] = useState<string | null>(memoryToken);

  const login = useCallback(async (email: string, _password: string): Promise<void> => {
    const response = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: _password }),
    });

    if (!response.ok) {
      throw new Error('Login failed');
    }

    const data = (await response.json()) as {
      access_token?: string;
      token?: string;
      user?: User;
    };

    // Support both old { token, user } and new { access_token } response shapes
    const accessToken = data.access_token ?? data.token ?? '';
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

    memoryToken = accessToken;
    setToken(accessToken);
    setUser(userInfo);
    sessionStorage.setItem('cipherradar-token', accessToken);
    sessionStorage.setItem('cipherradar-user', JSON.stringify(userInfo));
  }, []);

  const logout = useCallback((): void => {
    memoryToken = null;
    setToken(null);
    setUser(null);
    sessionStorage.removeItem('cipherradar-token');
    sessionStorage.removeItem('cipherradar-user');
  }, []);

  const value = useMemo(
    (): AuthContextValue => ({
      user,
      token,
      isAuthenticated: !!token && !!user,
      login,
      logout,
    }),
    [user, token, login, logout],
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
