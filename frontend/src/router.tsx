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

import { RepoComplianceUnified } from './pages/repo/RepoComplianceUnified.tsx';
import { RepoDependencies } from './pages/repo/RepoDependencies.tsx';
import { RepoSettings } from './pages/repo/RepoSettings.tsx';

import { CertificateTracker } from './pages/CertificateTracker.tsx';
import { ComplianceDashboard } from './pages/ComplianceDashboard.tsx';
import { CBOMDiff } from './pages/CBOMDiff.tsx';

import { NotificationPreferences } from './pages/NotificationPreferences.tsx';
import { OrgSettings } from './pages/admin/OrgSettings.tsx';
import { UserManagement } from './pages/admin/UserManagement.tsx';
import { IntegrationManagement } from './pages/admin/IntegrationManagement.tsx';
import { AuditLog } from './pages/admin/AuditLog.tsx';
import { AdminApiKeys } from './pages/admin/AdminApiKeys.tsx';
import { GroupManagement } from './pages/admin/GroupManagement.tsx';
import { LazyDependencyGraph } from './pages/LazyDependencyGraph.tsx';
import { PolicyRules } from './pages/PolicyRules.tsx';
import { RuntimeView } from './pages/RuntimeView.tsx';
import { AgilityScore } from './pages/AgilityScore.tsx';
import { HNDLRisk } from './pages/HNDLRisk.tsx';
import { CVECorrelation } from './pages/repo/CVECorrelation.tsx';
import { RequestQueue } from './pages/RequestQueue.tsx';
import { ScanQueue } from './pages/ScanQueue.tsx';
import { ArtifactRegistries } from './pages/admin/ArtifactRegistries.tsx';
import { LLMConfig } from './pages/admin/LLMConfig.tsx';
import { ForgotPassword } from './pages/ForgotPassword.tsx';
import { ResetPassword } from './pages/ResetPassword.tsx';
import { Onboarding } from './pages/Onboarding.tsx';
import { createRouteGuard } from './lib/route-guard.ts';

const rootRoute = createRootRoute({
  component: Outlet,
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  component: Login,
});

const forgotPasswordRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/forgot-password',
  component: ForgotPassword,
});

const resetPasswordRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/reset-password',
  component: ResetPassword,
  validateSearch: (search: Record<string, unknown>) => ({
    token: (search.token as string) ?? '',
  }),
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

const certTrackerRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/certificate-tracker',
  beforeLoad: createRouteGuard('certificates'),
  component: CertificateTracker,
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

const scansRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/scans',
  beforeLoad: createRouteGuard('scans'),
  component: ScanQueue,
});

const adminRegistriesRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/admin/registries',
  beforeLoad: createRouteGuard('admin-registries'),
  component: ArtifactRegistries,
});

const adminLLMConfigRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/admin/llm-config',
  beforeLoad: createRouteGuard('admin-llm-config'),
  component: LLMConfig,
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

const onboardingRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/onboarding',
  component: Onboarding,
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

const adminApiKeysRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/admin/api-keys',
  beforeLoad: createRouteGuard('admin-settings'),
  component: AdminApiKeys,
});

const adminGroupsRoute = createRoute({
  getParentRoute: () => authenticatedRoute,
  path: '/admin/groups',
  beforeLoad: createRouteGuard('admin-settings'),
  component: GroupManagement,
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
  component: RepoComplianceUnified,
});

const repoDependenciesRoute = createRoute({
  getParentRoute: () => repoLayoutRoute,
  path: '/dependencies',
  component: RepoDependencies,
});

const repoSettingsRoute = createRoute({
  getParentRoute: () => repoLayoutRoute,
  path: '/settings',
  component: RepoSettings,
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
  forgotPasswordRoute,
  resetPasswordRoute,
  authenticatedRoute.addChildren([
    dashboardRoute,
    assetsRoute,
    reposRoute,
    quantumRoute,
    complianceRoute,
    graphRoute,

    certTrackerRoute,
    complianceDashboardRoute,
    policyRoute,
    cbomDiffRoute,

    notificationPreferencesRoute,
    requestsRoute,
    scansRoute,
    profileRoute,
    downloadsRoute,
    onboardingRoute,
    adminSettingsRoute,
    adminUsersRoute,
    adminIntegrationsRoute,
    adminAuditLogRoute,
    adminApiKeysRoute,
    adminGroupsRoute,
    adminRegistriesRoute,
    adminLLMConfigRoute,
    repoScanDetailRoute,
    repoLayoutRoute.addChildren([
      repoOverviewRoute,
      repoScansRoute,
      repoFindingsRoute,
      repoComplianceRoute,
      repoDependenciesRoute,
      repoSettingsRoute,
      repoQuantumRoute,
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
