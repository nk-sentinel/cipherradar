import {
  createRouter,
  createRootRoute,
  createRoute,
  redirect,
  Outlet,
} from '@tanstack/react-router';
import { AppLayout } from './components/layout/AppLayout';
import { Login } from './pages/Login';
import { Dashboard } from './pages/Dashboard';

const rootRoute = createRootRoute({
  component: Outlet,
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  component: Login,
});

const authenticatedRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: 'authenticated',
  component: AppLayout,
  beforeLoad: () => {
    const token = sessionStorage.getItem('cipherradar-token');
    if (!token) {
      throw redirect({ to: '/login' });
    }
  },
});

const dashboardRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/',
  component: Dashboard,
});

const indexRedirectRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/dashboard',
  beforeLoad: () => {
    throw redirect({ to: '/' });
  },
  component: () => null,
});

const routeTree = rootRoute.addChildren([
  loginRoute,
  authenticatedRoute.addChildren([dashboardRoute]),
  indexRedirectRoute,
]);

export const router = createRouter({ routeTree });

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
