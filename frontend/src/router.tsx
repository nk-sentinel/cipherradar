import {
  createRouter,
  createRootRoute,
  createRoute,
  redirect,
  Outlet,
} from '@tanstack/react-router';
import { AppLayout } from './components/layout/AppLayout.tsx';
import { Login } from './pages/Login.tsx';
import { PortfolioDashboard } from './pages/PortfolioDashboard.tsx';
import { AssetExplorer } from './pages/AssetExplorer.tsx';
import { Repositories } from './pages/Repositories.tsx';
import { QuantumReadiness } from './pages/QuantumReadiness.tsx';
import { Compliance } from './pages/Compliance.tsx';
import { Profile } from './pages/Profile.tsx';
import { Downloads } from './pages/Downloads.tsx';
import { RepoLayout } from './pages/repo/RepoLayout.tsx';
import { RepoOverview } from './pages/repo/RepoOverview.tsx';
import { ScanHistoryPage } from './pages/repo/ScanHistoryPage.tsx';
import { ScanDetailPage } from './pages/repo/ScanDetailPage.tsx';
import { RepoFindingsPage } from './pages/repo/RepoFindingsPage.tsx';
import { RepoQuantum } from './pages/repo/RepoQuantum.tsx';
import { RepoCompliance } from './pages/repo/RepoCompliance.tsx';
import { CertCalendar } from './pages/CertCalendar.tsx';
import { ComplianceDashboard } from './pages/ComplianceDashboard.tsx';
import { CBOMDiff } from './pages/CBOMDiff.tsx';
import { MigrationKanban } from './pages/MigrationKanban.tsx';
import { NotificationPreferences } from './pages/NotificationPreferences.tsx';
import { OrgSettings } from './pages/admin/OrgSettings.tsx';
import { UserManagement } from './pages/admin/UserManagement.tsx';
import { IntegrationManagement } from './pages/admin/IntegrationManagement.tsx';
import { AuditLog } from './pages/admin/AuditLog.tsx';
import { LazyDependencyGraph } from './pages/LazyDependencyGraph.tsx';
import { PolicyRules } from './pages/PolicyRules.tsx';
import { RuntimeView } from './pages/RuntimeView.tsx';
import { AgilityScore } from './pages/AgilityScore.tsx';
import { HNDLRisk } from './pages/HNDLRisk.tsx';
import { CVECorrelation } from './pages/repo/CVECorrelation.tsx';
import { RequestQueue } from './pages/RequestQueue.tsx';
import { createRouteGuard } from './lib/route-guard.ts';

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
  beforeLoad: createRouteGuard('dashboard'),
  component: PortfolioDashboard,
});

const assetsRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/assets',
  beforeLoad: createRouteGuard('assets'),
  component: AssetExplorer,
});

const reposRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/repos',
  beforeLoad: createRouteGuard('repos'),
  component: Repositories,
});

const quantumRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/quantum',
  beforeLoad: createRouteGuard('portfolio-quantum'),
  component: QuantumReadiness,
});

const complianceRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/compliance',
  beforeLoad: createRouteGuard('portfolio-compliance'),
  component: Compliance,
});

const graphRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/graph',
  beforeLoad: createRouteGuard('graph'),
  component: LazyDependencyGraph,
});

const certCalendarRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/certificates',
  beforeLoad: createRouteGuard('certificates'),
  component: CertCalendar,
});

const complianceDashboardRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/compliance-dashboard',
  beforeLoad: createRouteGuard('compliance-dashboard'),
  component: ComplianceDashboard,
});

const cbomDiffRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/diff',
  beforeLoad: createRouteGuard('diff'),
  component: CBOMDiff,
});

const migrationKanbanRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/migration',
  beforeLoad: createRouteGuard('migration'),
  component: MigrationKanban,
});

const policyRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/policy',
  beforeLoad: createRouteGuard('policy'),
  component: PolicyRules,
});

const notificationPreferencesRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/notifications/preferences',
  beforeLoad: createRouteGuard('notification-preferences'),
  component: NotificationPreferences,
});

const requestsRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/requests',
  beforeLoad: createRouteGuard('requests'),
  component: RequestQueue,
});

const profileRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/profile',
  component: Profile,
});

const downloadsRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/downloads',
  component: Downloads,
});

/* ---- Admin routes ---- */

const adminSettingsRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/admin/settings',
  beforeLoad: createRouteGuard('admin-settings'),
  component: OrgSettings,
});

const adminUsersRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/admin/users',
  beforeLoad: createRouteGuard('admin-users'),
  component: UserManagement,
});

const adminIntegrationsRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/admin/integrations',
  beforeLoad: createRouteGuard('admin-integrations'),
  component: IntegrationManagement,
});

const adminAuditLogRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/admin/audit-log',
  beforeLoad: createRouteGuard('admin-audit-log'),
  component: AuditLog,
});

/* ---- Repo routes ---- */

const repoLayoutRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/repos/$repoId',
  beforeLoad: createRouteGuard('repos'),
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
  beforeLoad: createRouteGuard('repos'),
  component: ScanDetailPage,
});

const repoFindingsRoute = createRoute({
  getParentRoute: () => repoLayoutRoute,
  path: '/findings',
  component: RepoFindingsPage,
});

const repoQuantumRoute = createRoute({
  getParentRoute: () => repoLayoutRoute,
  path: '/quantum',
  component: RepoQuantum,
});

const repoComplianceRoute = createRoute({
  getParentRoute: () => repoLayoutRoute,
  path: '/compliance',
  component: RepoCompliance,
});

const repoRuntimeRoute = createRoute({
  getParentRoute: () => repoLayoutRoute,
  path: '/runtime',
  component: RuntimeView,
});

const repoAgilityRoute = createRoute({
  getParentRoute: () => repoLayoutRoute,
  path: '/agility',
  component: AgilityScore,
});

const repoHndlRiskRoute = createRoute({
  getParentRoute: () => repoLayoutRoute,
  path: '/hndl-risk',
  component: HNDLRisk,
});

const repoCveCorrelationRoute = createRoute({
  getParentRoute: () => repoLayoutRoute,
  path: '/cve-correlation',
  component: CVECorrelation,
});

const repoTabRoute = createRoute({
  getParentRoute: () => repoLayoutRoute,
  path: '/$tab',
  component: () => {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>
          Page not found. Select a tab from the navigation above.
        </p>
        <p style={{ marginTop: '8px' }}>
          <a href="/" style={{ color: 'var(--accent)', fontSize: '13px' }}>Back to Dashboard</a>
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
    assetsRoute,
    reposRoute,
    quantumRoute,
    complianceRoute,
    graphRoute,
    certCalendarRoute,
    complianceDashboardRoute,
    policyRoute,
    cbomDiffRoute,
    migrationKanbanRoute,
    notificationPreferencesRoute,
    requestsRoute,
    profileRoute,
    downloadsRoute,
    adminSettingsRoute,
    adminUsersRoute,
    adminIntegrationsRoute,
    adminAuditLogRoute,
    repoScanDetailRoute,
    repoLayoutRoute.addChildren([
      repoOverviewRoute,
      repoScansRoute,
      repoFindingsRoute,
      repoQuantumRoute,
      repoComplianceRoute,
      repoRuntimeRoute,
      repoAgilityRoute,
      repoHndlRiskRoute,
      repoCveCorrelationRoute,
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
