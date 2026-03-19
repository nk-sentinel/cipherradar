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

    const data = (await response.json()) as { token: string; user: User };
    memoryToken = data.token;
    setToken(data.token);
    setUser(data.user);
    sessionStorage.setItem('cipherradar-token', data.token);
    sessionStorage.setItem('cipherradar-user', JSON.stringify(data.user));
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
