import { http, HttpResponse } from 'msw';
import {
  MOCK_REPOSITORIES,
  MOCK_REPOSITORY_DETAILS,
} from './data/repositories.ts';
import { getScansForRepo, getScanDetail } from './data/scans.ts';
import { getPortfolioQuantum, getRepoQuantum } from './data/quantum.ts';
import { getPortfolioCompliance, getRepoCompliance } from './data/compliance.ts';
import { getPortfolioSummary, getHeatMap } from './data/portfolio.ts';
import { searchAssets } from './data/assets.ts';
import type { AssetFilters, AssetType, QuantumAssetStatus, ComplianceTag } from './data/assets.ts';
import { getGraphData } from './data/graph.ts';
import { getCertificates } from './data/certificates.ts';
import { getComplianceDashboard } from './data/complianceDashboard.ts';
import { getCBOMDiff, getScanSelectors } from './data/cbomDiff.ts';
import { getNotifications, getNotificationPreferences } from './data/notifications.ts';
import { getKanbanCards } from './data/kanban.ts';
import {
  getUserOrgs,
  getOrgSettings,
  getOrgUsers,
  getIntegrations,
  getAuditLog,
} from './data/admin.ts';

export const handlers = [
  http.get('/api/v1/health', () => {
    return HttpResponse.json({
      status: 'ok',
      version: '0.1.0',
    });
  }),

  http.post('/api/v1/auth/login', async ({ request }) => {
    const body = (await request.json()) as { email: string; password: string };

    // Mock: accept any email with password "password"
    if (body.password !== 'password') {
      return new HttpResponse(
        JSON.stringify({ error: 'Invalid credentials' }),
        { status: 401 },
      );
    }

    const name = body.email.split('@')[0] ?? 'User';
    const initials = name
      .split('.')
      .map((p: string) => p.charAt(0).toUpperCase())
      .join('')
      .slice(0, 2);

    return HttpResponse.json({
      token: 'mock-jwt-token-' + Date.now().toString(),
      user: {
        name: name.replace('.', ' ').replace(/\b\w/g, (c: string) => c.toUpperCase()),
        email: body.email,
        role: 'org-admin',
        initials: initials || 'U',
      },
    });
  }),

  http.get('/api/v1/projects', () => {
    return HttpResponse.json(MOCK_REPOSITORIES);
  }),

  http.get('/api/v1/projects/:id', ({ params }) => {
    const { id } = params;
    const detail = MOCK_REPOSITORY_DETAILS[id as string];
    if (!detail) {
      return new HttpResponse(
        JSON.stringify({ error: 'Repository not found' }),
        { status: 404 },
      );
    }
    return HttpResponse.json(detail);
  }),

  http.get('/api/v1/projects/:repoId/scans', ({ params }) => {
    const repoId = params['repoId'] as string;
    const scans = getScansForRepo(repoId);
    return HttpResponse.json(scans);
  }),

  http.get('/api/v1/scans/:scanId', ({ params }) => {
    const scanId = params['scanId'] as string;
    const scan = getScanDetail(scanId);
    if (!scan) {
      return new HttpResponse(
        JSON.stringify({ error: 'Scan not found' }),
        { status: 404 },
      );
    }
    return HttpResponse.json(scan);
  }),

  // Quantum readiness — portfolio
  http.get('/api/v1/portfolio/quantum', () => {
    return HttpResponse.json(getPortfolioQuantum());
  }),

  // Quantum readiness — per repo
  http.get('/api/v1/projects/:repoId/quantum-risk', ({ params }) => {
    const repoId = params['repoId'] as string;
    const data = getRepoQuantum(repoId);
    if (!data) {
      return new HttpResponse(
        JSON.stringify({ error: 'Repository not found' }),
        { status: 404 },
      );
    }
    return HttpResponse.json(data);
  }),

  // Compliance — portfolio
  http.get('/api/v1/portfolio/compliance', () => {
    return HttpResponse.json(getPortfolioCompliance());
  }),

  // Compliance — per repo
  http.get('/api/v1/projects/:repoId/compliance/nist-800-131a', ({ params }) => {
    const repoId = params['repoId'] as string;
    const data = getRepoCompliance(repoId);
    if (!data) {
      return new HttpResponse(
        JSON.stringify({ error: 'Repository not found' }),
        { status: 404 },
      );
    }
    return HttpResponse.json(data);
  }),

  // Portfolio dashboard — summary
  http.get('/api/v1/portfolio/summary', () => {
    return HttpResponse.json(getPortfolioSummary());
  }),

  // Portfolio dashboard — heat map
  http.get('/api/v1/portfolio/heatmap', () => {
    return HttpResponse.json(getHeatMap());
  }),

  // Asset explorer — search/filter
  http.get('/api/v1/assets', ({ request }) => {
    const url = new URL(request.url);
    const filters: AssetFilters = {};
    const typeParam = url.searchParams.get('type');
    if (typeParam) filters.type = typeParam as AssetType;
    const lang = url.searchParams.get('language');
    if (lang) filters.language = lang;
    const qs = url.searchParams.get('quantumStatus');
    if (qs) filters.quantumStatus = qs as QuantumAssetStatus;
    const comp = url.searchParams.get('compliance');
    if (comp) filters.compliance = comp as ComplianceTag;
    const search = url.searchParams.get('search');
    if (search) filters.search = search;

    const page = Number(url.searchParams.get('page') || '1');
    const pageSize = Number(url.searchParams.get('pageSize') || '15');

    return HttpResponse.json(searchAssets(filters, page, pageSize));
  }),

  // Dependency graph
  http.get('/api/v1/graph', () => {
    return HttpResponse.json(getGraphData());
  }),

  // Certificates
  http.get('/api/v1/certificates', () => {
    return HttpResponse.json(getCertificates());
  }),

  // Compliance dashboard (enhanced)
  http.get('/api/v1/compliance/dashboard', () => {
    return HttpResponse.json(getComplianceDashboard());
  }),

  // Compliance trends (new endpoint name)
  http.get('/api/v1/compliance/trends', () => {
    return HttpResponse.json(getComplianceDashboard());
  }),

  // CBOM Diff
  http.get('/api/v1/cbom/diff', () => {
    return HttpResponse.json(getCBOMDiff());
  }),

  // CBOM scan selectors
  http.get('/api/v1/cbom/scans', () => {
    return HttpResponse.json(getScanSelectors());
  }),

  // Notifications
  http.get('/api/v1/notifications', () => {
    return HttpResponse.json(getNotifications());
  }),

  http.patch('/api/v1/notifications/:id/read', () => {
    return HttpResponse.json({ success: true });
  }),

  http.post('/api/v1/notifications/read-all', () => {
    return HttpResponse.json({ success: true });
  }),

  // Notification preferences
  http.get('/api/v1/notifications/preferences', () => {
    return HttpResponse.json(getNotificationPreferences());
  }),

  http.put('/api/v1/notifications/preferences', async ({ request }) => {
    const body = await request.json();
    return HttpResponse.json(body);
  }),

  // Kanban
  http.get('/api/v1/kanban', () => {
    return HttpResponse.json(getKanbanCards());
  }),

  // User orgs
  http.get('/api/v1/user/orgs', () => {
    return HttpResponse.json(getUserOrgs());
  }),

  // Trigger scan
  http.post('/api/v1/projects/:projectId/scans/trigger', () => {
    return HttpResponse.json({ status: 'queued', scanId: 'scan-' + Date.now().toString() });
  }),

  // Admin: org settings
  http.get('/api/v1/admin/settings', () => {
    return HttpResponse.json(getOrgSettings());
  }),

  http.put('/api/v1/admin/settings', async ({ request }) => {
    const body = await request.json();
    return HttpResponse.json(body);
  }),

  // Admin: user invite
  http.post('/api/v1/admin/users/invite', async ({ request }) => {
    const body = await request.json();
    return HttpResponse.json({ success: true, ...body as object });
  }),

  // Admin: user list
  http.get('/api/v1/admin/users', () => {
    return HttpResponse.json(getOrgUsers());
  }),

  // Admin: integrations
  http.get('/api/v1/admin/integrations', () => {
    return HttpResponse.json(getIntegrations());
  }),

  // Admin: audit log
  http.get('/api/v1/admin/audit-log', () => {
    return HttpResponse.json(getAuditLog());
  }),
];
