import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider } from '@tanstack/react-router';
import { useEffect } from 'react';
import { router } from './router.tsx';
import { AuthProvider } from './lib/auth.tsx';
import { OrgProvider } from './lib/org-context.tsx';
import { getStoredTheme, applyTheme } from './lib/themes.ts';
import { useUserOrgs } from './api/hooks/useOrgs.ts';
import { Toaster } from './components/ui/Toast.tsx';
import type { Org } from './mocks/data/admin.ts';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
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
