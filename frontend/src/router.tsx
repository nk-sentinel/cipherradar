import {
  createRouter,
  createRootRoute,
  createRoute,
  redirect,
  Outlet,
} from '@tanstack/react-router';
import { AppLayout } from './components/layout/AppLayout.tsx';
import { Login } from './pages/Login.tsx';
import { Dashboard } from './pages/Dashboard.tsx';
import { Repositories } from './pages/Repositories.tsx';
import { RepoLayout } from './pages/repo/RepoLayout.tsx';
import { RepoOverview } from './pages/repo/RepoOverview.tsx';
import { ScanHistoryPage } from './pages/repo/ScanHistoryPage.tsx';
import { ScanDetailPage } from './pages/repo/ScanDetailPage.tsx';
import { RepoFindingsPage } from './pages/repo/RepoFindingsPage.tsx';

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

const reposRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/repos',
  component: Repositories,
});

const repoLayoutRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/repos/$repoId',
  component: RepoLayout,
});

const repoOverviewRoute = createRoute({
  getParentRoute: () => repoLayoutRoute,
  path: '/overview',
  component: RepoOverview,
});

const repoScansRoute = createRoute({
  getParentRoute: () => repoLayoutRoute,
  path: '/scans',
  component: ScanHistoryPage,
});

const repoScanDetailRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/repos/$repoId/scans/$scanId',
  component: ScanDetailPage,
});

const repoFindingsRoute = createRoute({
  getParentRoute: () => repoLayoutRoute,
  path: '/findings',
  component: RepoFindingsPage,
});

const repoTabRoute = createRoute({
  getParentRoute: () => repoLayoutRoute,
  path: '/$tab',
  component: () => {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>
          This tab will be implemented in a future milestone.
        </p>
      </div>
    );
  },
});

const repoIndexRoute = createRoute({
  getParentRoute: () => repoLayoutRoute,
  path: '/',
  beforeLoad: ({ params }) => {
    throw redirect({
      to: '/repos/$repoId/overview',
      params: { repoId: params.repoId },
    });
  },
  component: () => null,
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
  authenticatedRoute.addChildren([
    dashboardRoute,
    reposRoute,
    repoScanDetailRoute,
    repoLayoutRoute.addChildren([
      repoOverviewRoute,
      repoScansRoute,
      repoFindingsRoute,
      repoIndexRoute,
      repoTabRoute,
    ]),
  ]),
  indexRedirectRoute,
]);

export const router = createRouter({ routeTree });

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
