import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider } from '@tanstack/react-router';
import { useEffect } from 'react';
import { router } from './router';
import { AuthProvider } from './lib/auth';
import { getStoredTheme, applyTheme } from './lib/themes';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
});

export function App(): React.ReactElement {
  useEffect(() => {
    const theme = getStoredTheme();
    applyTheme(theme);
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <RouterProvider router={router} />
      </AuthProvider>
    </QueryClientProvider>
  );
}
