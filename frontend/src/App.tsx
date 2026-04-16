import { QueryCache, QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider } from '@tanstack/react-router';
import { useEffect } from 'react';
import { router } from './router.tsx';
import { AuthProvider } from './lib/auth.tsx';
import { OrgProvider } from './lib/org-context.tsx';
import { getStoredTheme, applyTheme } from './lib/themes.ts';
import { useUserOrgs } from './api/hooks/useOrgs.ts';
import { Toaster } from './components/ui/Toast.tsx';
import { ApiError } from './api/client.ts';
import type { Org } from './mocks/data/admin.ts';

/**
 * Global query error handler — if any query gets a 401, the session is
 * invalid. Clear it and redirect to login instead of showing a broken page.
 */
function handleGlobalQueryError(error: unknown): void {
  if (error instanceof ApiError && error.status === 401) {
    sessionStorage.removeItem('cipherradar-token');
    sessionStorage.removeItem('cipherradar-user');
    if (window.location.pathname !== '/login') {
      window.location.href = '/login?expired=1';
    }
  }
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: (failureCount, error) => {
        // Don't retry auth errors — redirect to login instead
        if (error instanceof ApiError && error.status === 401) return false;
        return failureCount < 1;
      },
    },
    mutations: {
      onError: handleGlobalQueryError,
    },
  },
  queryCache: new QueryCache({ onError: handleGlobalQueryError }),
});

function OrgBootstrap({ children }: { children: React.ReactNode }): React.ReactElement {
  const { data: orgs } = useUserOrgs();
  const rawOrgs = orgs as Org[] | { items?: Org[] } | undefined;
  const resolvedOrgs: Org[] = Array.isArray(rawOrgs) ? rawOrgs : (rawOrgs?.items ?? []);

  return <OrgProvider orgs={resolvedOrgs}>{children}</OrgProvider>;
}

export function App(): React.ReactElement {
  useEffect(() => {
    const theme = getStoredTheme();
    applyTheme(theme);
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <OrgBootstrap>
          <RouterProvider router={router} />
        </OrgBootstrap>
      </AuthProvider>
      <Toaster />
    </QueryClientProvider>
  );
}
