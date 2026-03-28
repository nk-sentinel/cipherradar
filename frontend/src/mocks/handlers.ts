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
  getAuditLog,
  getIntegrationsEnriched,
  getDiscoveredRepos,
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
  http.post('/api/v1/projects/:projectId/scans/trigger', async ({ request }) => {
    const body = await request.json() as Record<string, unknown>;
    return HttpResponse.json({
      status: 'queued',
      scanId: 'scan-' + Date.now().toString(),
      sourceType: body.sourceType ?? 'repository',
    });
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

  // Admin: user list (paginated)
  http.get('/api/v1/admin/users', ({ request }) => {
    const url = new URL(request.url);
    const page = Number(url.searchParams.get('page') || '1');
    const perPage = Number(url.searchParams.get('perPage') || '25');
    const search = url.searchParams.get('search') || '';
    const allUsers = getOrgUsers();
    const enriched = allUsers.map((u) => ({
      ...u,
      authSource: 'local',
      groups: [],
      apiKeyCount: 0,
      createdAt: '2026-01-15',
    }));
    const filtered = search
      ? enriched.filter(
          (u) =>
            u.name.toLowerCase().includes(search.toLowerCase()) ||
            u.email.toLowerCase().includes(search.toLowerCase()),
        )
      : enriched;
    const total = filtered.length;
    const start = (page - 1) * perPage;
    const items = filtered.slice(start, start + perPage);
    return HttpResponse.json({ items, total, page, perPage });
  }),

  // Admin: integrations (enriched with syncedRepoCount, tokenAge — D3)
  http.get('/api/v1/admin/integrations', () => {
    return HttpResponse.json(getIntegrationsEnriched());
  }),

  // Admin: connect provider (D3 PAT modal)
  http.post('/api/v1/admin/integrations/connect', async ({ request }) => {
    const body = await request.json() as { type: string; baseUrl: string; token: string };
    return HttpResponse.json({
      id: 'int-new-' + Date.now().toString(),
      type: body.type,
      label: body.type.charAt(0).toUpperCase() + body.type.slice(1),
      status: 'connected',
      connectedAt: new Date().toISOString(),
      detail: body.baseUrl,
      syncedRepoCount: 0,
      tokenAge: 0,
      tokenRotationWarning: false,
    });
  }),

  // Admin: disconnect provider (D3)
  http.post('/api/v1/admin/integrations/:providerId/disconnect', () => {
    return HttpResponse.json({ success: true });
  }),

  // Admin: test connection (D3)
  http.post('/api/v1/admin/integrations/:providerId/test', () => {
    return HttpResponse.json({
      success: true,
      message: 'Connection successful',
      latencyMs: 42,
    });
  }),

  // Admin: discover repos (D3 repo picker)
  http.get('/api/v1/admin/integrations/:providerId/repos', ({ request }) => {
    const url = new URL(request.url);
    const search = url.searchParams.get('search') || '';
    return HttpResponse.json(getDiscoveredRepos(search));
  }),

  // Admin: import repos (D3)
  http.post('/api/v1/admin/integrations/import', async ({ request }) => {
    const body = await request.json() as { repoIds: string[] };
    return HttpResponse.json({
      imported: body.repoIds.length,
      failed: 0,
      errors: [],
    });
  }),

  // Admin: audit log — moved to Plan 5 D28 section with pagination and filters

  // ---------------------------------------------------------------------------
  // D18 — Jira integration
  // ---------------------------------------------------------------------------

  // Create Jira issue for finding
  http.post('/api/v1/findings/:findingId/jira', ({ params }) => {
    const findingId = params['findingId'] as string;
    return HttpResponse.json({
      issueKey: 'SEC-' + findingId.slice(0, 4).toUpperCase(),
      issueUrl: 'https://jira.example.com/browse/SEC-' + findingId.slice(0, 4).toUpperCase(),
      summary: '[CipherRadar] CRITICAL: RSA-1024',
    });
  }),

  // Group Jira config
  http.get('/api/v1/groups/:groupId/jira-config', () => {
    return HttpResponse.json({
      id: 'jc-001',
      jiraProjectKey: 'SEC',
      defaultIssueType: 'Bug',
      priorityMapping: { critical: 'Highest', high: 'High', medium: 'Medium', low: 'Low' },
      customFields: {},
      defaultAssignee: null,
      labels: ['crypto', 'cipherradar'],
      scope: 'group',
    });
  }),

  http.put('/api/v1/groups/:groupId/jira-config', async ({ request }) => {
    const body = await request.json();
    return HttpResponse.json({
      id: 'jc-001',
      ...(body as object),
      scope: 'group',
    });
  }),

  // Project Jira config
  http.get('/api/v1/projects/:projectId/jira-config', () => {
    return HttpResponse.json({
      id: 'jc-002',
      jiraProjectKey: 'PROJ',
      defaultIssueType: 'Task',
      priorityMapping: {},
      customFields: {},
      defaultAssignee: 'dev@example.com',
      labels: [],
      scope: 'project',
    });
  }),

  http.put('/api/v1/projects/:projectId/jira-config', async ({ request }) => {
    const body = await request.json();
    return HttpResponse.json({
      id: 'jc-002',
      ...(body as object),
      scope: 'project',
    });
  }),

  // ---------------------------------------------------------------------------
  // D16 — Rule effectiveness analytics
  // ---------------------------------------------------------------------------

  // Single rule analytics
  http.get('/api/v1/admin/rules/:ruleId/analytics', ({ params, request }) => {
    const ruleId = params['ruleId'] as string;
    const url = new URL(request.url);
    const timeWindow = url.searchParams.get('time_window') || '90d';
    return HttpResponse.json({
      ruleId,
      totalFindings: 42,
      activeFindings: 15,
      fpRate: 12.5,
      raRate: 5.0,
      fixRate: 60.0,
      mttrSeconds: 172800,
      trend: [
        { scanId: 'scan-001', count: 8, scannedAt: '2026-03-20T10:00:00Z' },
        { scanId: 'scan-002', count: 6, scannedAt: '2026-03-22T10:00:00Z' },
        { scanId: 'scan-003', count: 4, scannedAt: '2026-03-24T10:00:00Z' },
      ],
      timeWindow,
    });
  }),

  // Rules summary table
  http.get('/api/v1/admin/rules/summary', () => {
    return HttpResponse.json([
      { ruleId: 'cbom-python-md5-usage', totalFindings: 42, fpRate: 12.5, fixRate: 60.0, mttrSeconds: 172800, warning: false },
      { ruleId: 'cbom-java-weak-rsa', totalFindings: 28, fpRate: 55.0, fixRate: 8.0, mttrSeconds: null, warning: true },
      { ruleId: 'cbom-go-des-usage', totalFindings: 15, fpRate: 5.0, fixRate: 80.0, mttrSeconds: 86400, warning: false },
    ]);
  }),

  // ---------------------------------------------------------------------------
  // D13 — Finding status change
  // ---------------------------------------------------------------------------

  http.patch('/api/v1/findings/:findingId/status', async ({ request, params }) => {
    const body = await request.json() as { status: string; reason?: string };
    return HttpResponse.json({
      id: params['findingId'],
      status: body.status,
      assignedTo: null,
      updatedAt: new Date().toISOString(),
    });
  }),

  // Finding status history
  http.get('/api/v1/findings/:findingId/history', ({ request }) => {
    const url = new URL(request.url);
    const page = Number(url.searchParams.get('page') || '1');
    const perPage = Number(url.searchParams.get('perPage') || '25');
    return HttpResponse.json({
      items: [
        {
          id: 'hist-001',
          oldStatus: 'open',
          newStatus: 'in_review',
          changedBy: 'user-001',
          reason: null,
          createdAt: '2026-03-25T10:00:00Z',
        },
      ],
      total: 1,
      page,
      perPage,
    });
  }),

  // ---------------------------------------------------------------------------
  // D15 — FP/RA requests
  // ---------------------------------------------------------------------------

  http.post('/api/v1/findings/:findingId/request', async ({ request, params }) => {
    const body = await request.json() as {
      requestType: string;
      justification: string;
    };
    return HttpResponse.json({
      id: 'req-' + Date.now().toString(),
      findingId: params['findingId'],
      requestedBy: 'user-001',
      reviewedBy: null,
      requestType: body.requestType,
      status: 'pending',
      justification: body.justification,
      reviewNote: null,
      expiresAt: null,
      reviewedAt: null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
  }),

  http.get('/api/v1/requests', ({ request }) => {
    const url = new URL(request.url);
    const page = Number(url.searchParams.get('page') || '1');
    const perPage = Number(url.searchParams.get('perPage') || '25');
    const items = [
      {
        id: 'req-001',
        findingId: 'f-001',
        findingSummary: 'Certificate validation disabled',
        findingSeverity: 'critical',
        requester: 'alice@example.com',
        type: 'false_positive',
        justification: 'This is a test environment configuration that is not used in production.',
        status: 'pending',
        createdAt: '2026-03-20T10:00:00Z',
      },
      {
        id: 'req-002',
        findingId: 'f-006',
        findingSummary: 'RSA-2048 key generation',
        findingSeverity: 'medium',
        requester: 'bob@example.com',
        type: 'risk_accepted',
        justification: 'Migration to ML-KEM is planned for Q3. Compensating control: key rotation every 30 days.',
        reasonCategory: 'migration_planned',
        reviewDate: '2026-06-30',
        status: 'pending',
        createdAt: '2026-03-21T14:00:00Z',
      },
      {
        id: 'req-003',
        findingId: 'f-004',
        findingSummary: 'SHA-1 signature verification',
        findingSeverity: 'high',
        requester: 'charlie@example.com',
        type: 'false_positive',
        justification: 'This SHA-1 usage is for non-security checksum validation only.',
        status: 'pending',
        createdAt: '2026-03-22T09:00:00Z',
      },
    ];
    const total = items.length;
    const start = (page - 1) * perPage;
    const paginated = items.slice(start, start + perPage);
    return HttpResponse.json({ items: paginated, total });
  }),

  http.post('/api/v1/requests/:requestId/approve', ({ params }) => {
    return HttpResponse.json({
      id: params['requestId'],
      status: 'approved',
      updatedAt: new Date().toISOString(),
    });
  }),

  http.post('/api/v1/requests/:requestId/reject', async ({ request, params }) => {
    const body = await request.json() as { reason: string };
    return HttpResponse.json({
      id: params['requestId'],
      status: 'rejected',
      rejectionReason: body.reason,
      updatedAt: new Date().toISOString(),
    });
  }),

  // ---------------------------------------------------------------------------
  // D17 — Finding assignment
  // ---------------------------------------------------------------------------

  http.patch('/api/v1/findings/:findingId/assign', async ({ request, params }) => {
    const body = await request.json() as { assigneeId: string | null };
    return HttpResponse.json({
      id: params['findingId'],
      status: 'in_review',
      assignedTo: body.assigneeId,
      updatedAt: new Date().toISOString(),
    });
  }),

  http.get('/api/v1/projects/:projectId/members', () => {
    return HttpResponse.json([
      { email: 'alice@example.com', name: 'Alice Smith', role: 'security-engineer' },
      { email: 'bob@example.com', name: 'Bob Jones', role: 'developer' },
      { email: 'charlie@example.com', name: 'Charlie Brown', role: 'team-manager' },
      { email: 'dave@example.com', name: 'Dave Wilson', role: 'security-manager' },
    ]);
  }),

  // ---------------------------------------------------------------------------
  // D19 — Bulk actions
  // ---------------------------------------------------------------------------

  http.post('/api/v1/findings/bulk', async ({ request }) => {
    const body = await request.json() as {
      findingIds: string[];
      action: string;
      params?: Record<string, unknown>;
    };
    const results = body.findingIds.map((id: string) => ({
      findingId: id,
      success: true,
      error: null,
    }));
    return HttpResponse.json({
      total: body.findingIds.length,
      succeeded: body.findingIds.length,
      failed: 0,
      results,
    });
  }),

  // ---------------------------------------------------------------------------
  // D20 — Scan queue (enhanced list with filters and pagination)
  // ---------------------------------------------------------------------------

  http.get('/api/v1/scans', ({ request }) => {
    const url = new URL(request.url);
    const status = url.searchParams.get('status');
    const projectId = url.searchParams.get('projectId');
    const page = Number(url.searchParams.get('page') || '1');
    const perPage = Number(url.searchParams.get('perPage') || '25');

    const allScans = [
      {
        id: 'scan-001',
        projectId: 'proj-001',
        projectName: 'auth-service',
        status: 'completed',
        branch: 'main',
        commitSha: 'abc123',
        triggerType: 'manual',
        triggeredBy: 'alice@example.com',
        findingsCount: 12,
        startedAt: '2026-03-25T10:00:00Z',
        completedAt: '2026-03-25T10:05:00Z',
        createdAt: '2026-03-25T09:59:00Z',
        durationSeconds: 300,
        environment: 'dev',
      },
      {
        id: 'scan-002',
        projectId: 'proj-002',
        projectName: 'payment-gateway',
        status: 'running',
        branch: 'feature/pqc',
        commitSha: 'def456',
        triggerType: 'webhook',
        triggeredBy: 'github',
        findingsCount: 0,
        startedAt: '2026-03-27T08:00:00Z',
        completedAt: null,
        createdAt: '2026-03-27T07:59:00Z',
        durationSeconds: null,
        environment: null,
      },
      {
        id: 'scan-003',
        projectId: 'proj-001',
        projectName: 'auth-service',
        status: 'queued',
        branch: 'main',
        commitSha: null,
        triggerType: 'schedule',
        triggeredBy: 'cron',
        findingsCount: 0,
        startedAt: null,
        completedAt: null,
        createdAt: '2026-03-27T09:00:00Z',
        durationSeconds: null,
        environment: null,
      },
    ];

    let filtered = allScans;
    if (status) filtered = filtered.filter(s => s.status === status);
    if (projectId) filtered = filtered.filter(s => s.projectId === projectId);

    const total = filtered.length;
    const start = (page - 1) * perPage;
    const items = filtered.slice(start, start + perPage);

    return HttpResponse.json({ items, total, page, perPage });
  }),

  // Scan rerun
  http.post('/api/v1/scans/:scanId/rerun', () => {
    return HttpResponse.json({
      id: 'scan-rerun-' + Date.now().toString(),
      projectId: 'proj-001',
      status: 'queued',
      branch: 'main',
      commitSha: null,
      findingsCount: 0,
      startedAt: null,
      completedAt: null,
      createdAt: new Date().toISOString(),
    });
  }),

  // ---------------------------------------------------------------------------
  // D20 — Scan schedule
  // ---------------------------------------------------------------------------

  // Project schedule
  http.get('/api/v1/projects/:projectId/schedule', () => {
    return HttpResponse.json({
      cron: '0 2 * * *',
      timezone: 'UTC',
      source: 'project',
      nextRun: '2026-03-28T02:00:00Z',
    });
  }),

  http.put('/api/v1/projects/:projectId/schedule', async ({ request }) => {
    const body = await request.json() as { preset?: string; cron?: string; timezone?: string };
    const cron = body.preset === 'daily' ? '0 2 * * *'
      : body.preset === 'weekly' ? '0 2 * * 0'
      : body.cron || '0 2 * * *';
    return HttpResponse.json({
      cron,
      timezone: body.timezone || 'UTC',
      source: 'project',
      nextRun: '2026-03-28T02:00:00Z',
    });
  }),

  // Group schedule
  http.get('/api/v1/groups/:groupId/schedule', () => {
    return HttpResponse.json({
      cron: '0 3 * * 0',
      timezone: 'UTC',
      source: 'group',
      nextRun: '2026-03-30T03:00:00Z',
    });
  }),

  http.put('/api/v1/groups/:groupId/schedule', async ({ request }) => {
    const body = await request.json() as { preset?: string; cron?: string; timezone?: string };
    const cron = body.cron || '0 3 * * 0';
    return HttpResponse.json({
      cron,
      timezone: body.timezone || 'UTC',
      source: 'group',
      nextRun: '2026-03-30T03:00:00Z',
    });
  }),

  // ---------------------------------------------------------------------------
  // D21 — Scan provenance and promotion
  // ---------------------------------------------------------------------------

  http.get('/api/v1/scans/:scanId/provenance', ({ params }) => {
    return HttpResponse.json({
      scanId: params['scanId'],
      projectId: 'proj-001',
      branch: 'main',
      commitSha: 'abc123def456',
      tag: 'v1.2.0',
      imageRef: 'ghcr.io/org/app:v1.2.0',
      imageDigest: 'sha256:abc123',
      artifactFilename: null,
      artifactChecksum: null,
      environment: 'staging',
      promotedAt: '2026-03-26T14:00:00Z',
      promotedBy: 'user-001',
      createdAt: '2026-03-25T10:00:00Z',
    });
  }),

  http.post('/api/v1/scans/promote', async ({ request }) => {
    const body = await request.json() as { scanId: string; fromEnv: string; toEnv: string };
    return HttpResponse.json({
      scanId: body.scanId,
      projectId: 'proj-001',
      branch: 'main',
      commitSha: 'abc123def456',
      tag: 'v1.2.0',
      imageRef: 'ghcr.io/org/app:v1.2.0',
      imageDigest: 'sha256:abc123',
      artifactFilename: null,
      artifactChecksum: null,
      environment: body.toEnv,
      promotedAt: new Date().toISOString(),
      promotedBy: 'user-001',
      createdAt: '2026-03-25T10:00:00Z',
    });
  }),

  // Environment stages
  http.get('/api/v1/admin/environments', () => {
    return HttpResponse.json([
      { id: 'env-001', name: 'dev', displayOrder: 0, color: '#22c55e', isProduction: false },
      { id: 'env-002', name: 'staging', displayOrder: 1, color: '#eab308', isProduction: false },
      { id: 'env-003', name: 'production', displayOrder: 2, color: '#ef4444', isProduction: true },
    ]);
  }),

  http.put('/api/v1/admin/environments', async ({ request }) => {
    const body = await request.json();
    return HttpResponse.json(body);
  }),

  // ---------------------------------------------------------------------------
  // D2 — Artifact registries
  // ---------------------------------------------------------------------------

  http.get('/api/v1/admin/registries', () => {
    return HttpResponse.json([
      {
        id: 'reg-001',
        orgId: 'org-001',
        name: 'JFrog Artifactory',
        registryType: 'jfrog',
        url: 'https://myorg.jfrog.io',
        enabled: true,
        createdAt: '2026-01-15T10:00:00Z',
        updatedAt: '2026-03-20T14:00:00Z',
      },
      {
        id: 'reg-002',
        orgId: 'org-001',
        name: 'AWS ECR',
        registryType: 'ecr',
        url: 'https://123456789.dkr.ecr.us-east-1.amazonaws.com',
        enabled: true,
        createdAt: '2026-02-01T10:00:00Z',
        updatedAt: '2026-03-20T14:00:00Z',
      },
    ]);
  }),

  http.get('/api/v1/admin/registries/:registryId', ({ params }) => {
    return HttpResponse.json({
      id: params['registryId'],
      orgId: 'org-001',
      name: 'JFrog Artifactory',
      registryType: 'jfrog',
      url: 'https://myorg.jfrog.io',
      enabled: true,
      createdAt: '2026-01-15T10:00:00Z',
      updatedAt: '2026-03-20T14:00:00Z',
    });
  }),

  http.post('/api/v1/admin/registries', async ({ request }) => {
    const body = await request.json() as Record<string, unknown>;
    return HttpResponse.json({
      id: 'reg-' + Date.now().toString(),
      orgId: 'org-001',
      ...body,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }, { status: 201 });
  }),

  http.put('/api/v1/admin/registries/:registryId', async ({ request, params }) => {
    const body = await request.json() as Record<string, unknown>;
    return HttpResponse.json({
      id: params['registryId'],
      orgId: 'org-001',
      name: 'JFrog Artifactory',
      registryType: 'jfrog',
      url: 'https://myorg.jfrog.io',
      enabled: true,
      ...body,
      updatedAt: new Date().toISOString(),
    });
  }),

  http.delete('/api/v1/admin/registries/:registryId', () => {
    return new HttpResponse(null, { status: 204 });
  }),

  http.post('/api/v1/admin/registries/:registryId/test', () => {
    return HttpResponse.json({
      success: true,
      message: 'Successfully connected to registry',
      latencyMs: 42,
    });
  }),

  // ---------------------------------------------------------------------------
  // Plan 4 — Password management (D6, D30)
  // ---------------------------------------------------------------------------

  http.put('/api/v1/auth/password', async ({ request }) => {
    const body = await request.json() as { currentPassword: string; newPassword: string };
    if (body.currentPassword === 'wrong') {
      return new HttpResponse(
        JSON.stringify({ detail: 'Current password is incorrect' }),
        { status: 400 },
      );
    }
    return HttpResponse.json({ message: 'Password changed successfully' });
  }),

  http.put('/api/v1/admin/users/:userId/reset-password', () => {
    return HttpResponse.json({
      tempPassword: 'temp_' + Date.now().toString(),
      message: 'Temporary password generated',
    });
  }),

  http.post('/api/v1/auth/forgot-password', async () => {
    return HttpResponse.json({
      message: 'If the email is registered, a reset link has been sent',
    });
  }),

  http.post('/api/v1/auth/reset-password', async ({ request }) => {
    const body = await request.json() as { token: string; newPassword: string };
    if (body.token === 'expired') {
      return new HttpResponse(
        JSON.stringify({ detail: 'Invalid or expired reset token' }),
        { status: 400 },
      );
    }
    return HttpResponse.json({ message: 'Password has been reset successfully' });
  }),

  // ---------------------------------------------------------------------------
  // Plan 4 — API key management (D7)
  // ---------------------------------------------------------------------------

  http.get('/api/v1/auth/api-keys', () => {
    return HttpResponse.json({
      items: [
        {
          id: 'key-001',
          name: 'CI Pipeline',
          keyPrefix: 'cbom_sk_xxxx',
          scopes: ['scan:read', 'scan:write'],
          createdAt: '2026-03-15T10:00:00Z',
          expiresAt: null,
          lastUsedAt: '2026-03-27T08:00:00Z',
          revokedAt: null,
        },
        {
          id: 'key-002',
          name: 'Read-only',
          keyPrefix: 'cbom_sk_yyyy',
          scopes: ['scan:read'],
          createdAt: '2026-03-20T14:00:00Z',
          expiresAt: '2026-06-20T14:00:00Z',
          lastUsedAt: null,
          revokedAt: null,
        },
      ],
      total: 2,
    });
  }),

  http.post('/api/v1/auth/api-keys', async ({ request }) => {
    const body = await request.json() as { name: string; scopes: string[] };
    return HttpResponse.json(
      {
        id: 'key-' + Date.now().toString(),
        name: body.name,
        key: 'cbom_sk_' + Date.now().toString() + '_full_key_shown_once',
        keyPrefix: 'cbom_sk_' + Date.now().toString().slice(0, 4),
        scopes: body.scopes,
        createdAt: new Date().toISOString(),
        expiresAt: null,
      },
      { status: 201 },
    );
  }),

  http.delete('/api/v1/auth/api-keys/:keyId', () => {
    return HttpResponse.json({ message: 'API key revoked successfully' });
  }),

  http.get('/api/v1/admin/api-keys', () => {
    return HttpResponse.json({
      items: [
        {
          id: 'key-001',
          name: 'CI Pipeline',
          keyPrefix: 'cbom_sk_xxxx',
          owner: 'alex.chen@nk-sentinel.io',
          scopes: ['scan:read', 'scan:write'],
          createdAt: '2026-03-15T10:00:00Z',
          expiresAt: null,
          lastUsedAt: '2026-03-27T08:00:00Z',
          revokedAt: null,
          status: 'active',
        },
        {
          id: 'key-002',
          name: 'Read-only Dashboard',
          keyPrefix: 'cbom_sk_yyyy',
          owner: 'sarah.kim@nk-sentinel.io',
          scopes: ['scan:read'],
          createdAt: '2026-03-20T14:00:00Z',
          expiresAt: '2026-06-20T14:00:00Z',
          lastUsedAt: null,
          revokedAt: null,
          status: 'active',
        },
        {
          id: 'key-003',
          name: 'Legacy Integration',
          keyPrefix: 'cbom_sk_zzzz',
          owner: 'alex.chen@nk-sentinel.io',
          scopes: ['scan:read', 'scan:write', 'cbom:read'],
          createdAt: '2026-01-10T10:00:00Z',
          expiresAt: null,
          lastUsedAt: '2026-01-15T08:00:00Z',
          revokedAt: null,
          status: 'active',
        },
        {
          id: 'key-004',
          name: 'Revoked Key',
          keyPrefix: 'cbom_sk_rrrr',
          owner: 'james.liu@nk-sentinel.io',
          scopes: ['scan:read'],
          createdAt: '2026-02-01T10:00:00Z',
          expiresAt: null,
          lastUsedAt: '2026-02-15T08:00:00Z',
          revokedAt: '2026-03-01T10:00:00Z',
          status: 'revoked',
        },
      ],
      total: 4,
    });
  }),

  http.delete('/api/v1/admin/api-keys/:keyId', () => {
    return HttpResponse.json({ message: 'API key revoked successfully' });
  }),

  // ---------------------------------------------------------------------------
  // Plan 4 — User lifecycle (D9)
  // ---------------------------------------------------------------------------

  http.put('/api/v1/admin/users/:userId/role', async ({ request, params }) => {
    const body = await request.json() as { role: string };
    return HttpResponse.json({
      userId: params['userId'],
      oldRole: 'developer',
      newRole: body.role,
      revokedKeys: 0,
    });
  }),

  http.patch('/api/v1/admin/users/:userId/role', async ({ request, params }) => {
    const body = await request.json() as { role: string };
    return HttpResponse.json({
      userId: params['userId'],
      oldRole: 'developer',
      newRole: body.role,
      revokedKeys: 0,
    });
  }),

  // Direct user add
  http.post('/api/v1/admin/users', async ({ request }) => {
    const body = await request.json() as Record<string, unknown>;
    return HttpResponse.json({
      id: 'u-' + Date.now().toString(),
      ...body,
      status: 'active',
      createdAt: new Date().toISOString(),
    }, { status: 201 });
  }),

  http.post('/api/v1/admin/users/:userId/disable', ({ params }) => {
    return HttpResponse.json({
      userId: params['userId'],
      status: 'disabled',
      message: 'User has been disabled',
    });
  }),

  http.post('/api/v1/admin/users/:userId/enable', ({ params }) => {
    return HttpResponse.json({
      userId: params['userId'],
      status: 'active',
      message: 'User has been re-enabled',
    });
  }),

  http.delete('/api/v1/admin/users/:userId', ({ params }) => {
    return HttpResponse.json({
      userId: params['userId'],
      message: 'User scheduled for deletion (30-day grace period)',
    });
  }),

  // ---------------------------------------------------------------------------
  // Plan 4 — Recovery (D9)
  // ---------------------------------------------------------------------------

  http.post('/api/v1/auth/recover', async ({ request }) => {
    const body = await request.json() as { recoveryKey: string };
    if (body.recoveryKey !== 'valid-recovery-key') {
      return new HttpResponse(
        JSON.stringify({ detail: 'Invalid recovery key' }),
        { status: 401 },
      );
    }
    return HttpResponse.json({
      message: 'Password reset successfully. Change it immediately.',
    });
  }),

  // ---------------------------------------------------------------------------
  // Plan 5 — LLM Configuration (D5)
  // ---------------------------------------------------------------------------

  http.get('/api/v1/admin/llm-config', () => {
    return HttpResponse.json({
      provider: 'anthropic',
      apiUrl: 'https://api.anthropic.com',
      apiKey: 'sk-ant-****',
      model: 'claude-sonnet-4-20250514',
      temperature: 0.2,
      maxTokens: 4096,
      privacy: {
        consentRequired: true,
        stripComments: false,
        anonymizeVariables: false,
      },
      customInstructions: '',
    });
  }),

  http.put('/api/v1/admin/llm-config', async ({ request }) => {
    const body = await request.json();
    return HttpResponse.json(body);
  }),

  http.post('/api/v1/admin/llm-config/test', async () => {
    return HttpResponse.json({
      success: true,
      message: 'Connection successful',
      latencyMs: 245,
      model: 'claude-sonnet-4-20250514',
    });
  }),

  // ---------------------------------------------------------------------------
  // Plan 5 — Policy Configuration (D26)
  // ---------------------------------------------------------------------------

  http.get('/api/v1/admin/policy', () => {
    return HttpResponse.json({
      rules: [
        { id: 'no-broken-algorithms', severity: 'critical', enabled: true, locked: true, scope: 'org', inheritedFrom: null },
        { id: 'no-ecb-mode', severity: 'high', enabled: true, locked: false, scope: 'org', inheritedFrom: null },
        { id: 'rsa-min-key-size', severity: 'high', enabled: true, locked: false, scope: 'group', inheritedFrom: 'Engineering' },
        { id: 'no-deprecated-tls', severity: 'high', enabled: true, locked: false, scope: 'org', inheritedFrom: null },
        { id: 'quantum-vulnerable', severity: 'medium', enabled: true, locked: false, scope: 'project', inheritedFrom: 'auth-service' },
        { id: 'no-hardcoded-keys', severity: 'critical', enabled: true, locked: true, scope: 'org', inheritedFrom: null },
      ],
    });
  }),

  http.put('/api/v1/admin/policy', async ({ request }) => {
    const body = await request.json();
    return HttpResponse.json(body);
  }),

  // ---------------------------------------------------------------------------
  // Plan 5 — Custom Rules (D27)
  // ---------------------------------------------------------------------------

  http.get('/api/v1/admin/rules', ({ request }) => {
    const url = new URL(request.url);
    const source = url.searchParams.get('source');
    const lang = url.searchParams.get('language');
    const sev = url.searchParams.get('severity');
    const search = url.searchParams.get('search');

    let rules = [
      { id: 'cbom-python-md5-usage', name: 'MD5 Usage (Python)', language: 'python', severity: 'critical', source: 'built-in', enabled: true, description: 'Detects hashlib.md5() usage' },
      { id: 'cbom-java-weak-rsa', name: 'Weak RSA Keys (Java)', language: 'java', severity: 'high', source: 'built-in', enabled: true, description: 'Detects RSA keys below 2048 bits' },
      { id: 'cbom-go-des-usage', name: 'DES Usage (Go)', language: 'go', severity: 'critical', source: 'built-in', enabled: true, description: 'Detects DES cipher usage' },
      { id: 'custom-python-sha1-hmac', name: 'SHA-1 HMAC (Python)', language: 'python', severity: 'high', source: 'custom', enabled: true, description: 'Custom rule for SHA-1 HMAC detection' },
      { id: 'custom-java-ecb-mode', name: 'ECB Mode (Java)', language: 'java', severity: 'high', source: 'custom', enabled: false, description: 'Custom fork detecting ECB mode' },
    ];

    if (source) rules = rules.filter(r => r.source === source);
    if (lang) rules = rules.filter(r => r.language === lang);
    if (sev) rules = rules.filter(r => r.severity === sev);
    if (search) {
      const q = search.toLowerCase();
      rules = rules.filter(r => r.name.toLowerCase().includes(q) || r.id.toLowerCase().includes(q));
    }

    return HttpResponse.json(rules);
  }),

  http.post('/api/v1/admin/rules', async ({ request }) => {
    const body = await request.json() as Record<string, unknown>;
    return HttpResponse.json({
      id: 'custom-' + Date.now().toString(),
      ...body,
      source: 'custom',
      enabled: false,
    }, { status: 201 });
  }),

  http.post('/api/v1/admin/rules/validate', async ({ request }) => {
    const body = await request.json() as { yaml: string };
    const valid = body.yaml.includes('rules:');
    return HttpResponse.json({
      valid,
      errors: valid ? [] : ['Missing required field: rules'],
    });
  }),

  http.post('/api/v1/admin/rules/dry-run', async ({ request }) => {
    const body = await request.json() as { yaml: string };
    return HttpResponse.json({
      matchCount: body.yaml.length > 50 ? 3 : 0,
      sampleMatches: [
        { file: 'src/crypto.py', line: 42, snippet: 'hashlib.md5(data)' },
      ],
    });
  }),

  http.post('/api/v1/admin/rules/:ruleId/fork', ({ params }) => {
    return HttpResponse.json({
      id: 'custom-fork-' + (params['ruleId'] as string),
      name: 'Fork of ' + (params['ruleId'] as string),
      source: 'custom',
      enabled: false,
      yaml: 'rules:\\n  - id: custom-fork-example\\n    patterns:\\n      - pattern: ...',
    });
  }),

  http.put('/api/v1/admin/rules/:ruleId', async ({ request, params }) => {
    const body = await request.json() as Record<string, unknown>;
    return HttpResponse.json({ id: params['ruleId'], ...body });
  }),

  http.delete('/api/v1/admin/rules/:ruleId', ({ params }) => {
    return HttpResponse.json({ id: params['ruleId'], deleted: true });
  }),

  http.post('/api/v1/admin/rules/:ruleId/test', async ({ params }) => {
    return HttpResponse.json({
      ruleId: params['ruleId'],
      ruleName: 'Test Rule',
      matches: [{ line: 1, code: 'hashlib.md5(data)', message: 'Matched' }],
      matchCount: 1,
    });
  }),

  http.get('/api/v1/rules/delta', () => {
    return HttpResponse.json({ items: [], total: 0 });
  }),

  // Policy cascade endpoints (D26)
  http.get('/api/v1/policy/effective', () => {
    return HttpResponse.json({
      rules: [
        { id: 'no-broken-algorithms', severity: 'critical', enabled: true, action: 'fail' },
        { id: 'no-ecb-mode', severity: 'high', enabled: true, action: 'fail' },
        { id: 'no-hardcoded-keys', severity: 'critical', enabled: true, action: 'fail' },
      ],
      lockedRules: ['no-broken-algorithms', 'no-hardcoded-keys'],
      scope: 'org',
    });
  }),

  http.put('/api/v1/policy/effective', async ({ request }) => {
    const body = await request.json() as { ruleId: string; action: string };
    return HttpResponse.json({ ruleId: body.ruleId, action: body.action, saved: true });
  }),

  http.get('/api/v1/policy/groups/:groupId/effective', () => {
    return HttpResponse.json({
      rules: [{ id: 'no-broken-algorithms', severity: 'critical', enabled: true, action: 'fail' }],
      lockedRules: ['no-broken-algorithms'],
      scope: 'group',
    });
  }),

  http.put('/api/v1/policy/groups/:groupId/effective', async ({ request }) => {
    const body = await request.json() as { ruleId: string; action: string };
    return HttpResponse.json({ ruleId: body.ruleId, action: body.action, saved: true });
  }),

  http.get('/api/v1/policy/projects/:projectId/effective', () => {
    return HttpResponse.json({
      rules: [{ id: 'no-broken-algorithms', severity: 'critical', enabled: true, action: 'fail' }],
      lockedRules: ['no-broken-algorithms'],
      scope: 'project',
    });
  }),

  http.put('/api/v1/policy/projects/:projectId/effective', async ({ request }) => {
    const body = await request.json() as { ruleId: string; action: string };
    return HttpResponse.json({ ruleId: body.ruleId, action: body.action, saved: true });
  }),

  // Integration management (D3)
  http.post('/api/v1/admin/integrations/:provider/connect', async ({ params }) => {
    return HttpResponse.json({
      id: 'int-' + Date.now().toString(),
      provider: params['provider'],
      status: 'connected',
      connectedAt: new Date().toISOString(),
    });
  }),

  http.delete('/api/v1/admin/integrations/:provider/connect', ({ params }) => {
    return HttpResponse.json({ provider: params['provider'], status: 'disconnected' });
  }),

  http.post('/api/v1/admin/integrations/:provider/test', ({ params }) => {
    return HttpResponse.json({ ok: true, provider: params['provider'] });
  }),

  http.get('/api/v1/admin/integrations/:provider/repos', ({ params }) => {
    return HttpResponse.json({
      repos: [
        { name: 'payment-service', url: `https://${params['provider'] as string}.com/org/payment-service`, defaultBranch: 'main' },
        { name: 'auth-api', url: `https://${params['provider'] as string}.com/org/auth-api`, defaultBranch: 'main' },
      ],
      total: 2,
    });
  }),

  http.post('/api/v1/admin/integrations/import', async ({ request }) => {
    const body = await request.json() as { repos: unknown[]; provider: string };
    return HttpResponse.json({
      imported: Array.isArray(body.repos) ? body.repos.length : 0,
      provider: body.provider,
    });
  }),

  // ---------------------------------------------------------------------------
  // Plan 5 — Audit Log Enhanced (D28)
  // ---------------------------------------------------------------------------

  http.get('/api/v1/admin/audit-log', ({ request }) => {
    const url = new URL(request.url);
    const page = Number(url.searchParams.get('page') || '1');
    const perPage = Number(url.searchParams.get('perPage') || '25');
    const userFilter = url.searchParams.get('user');
    const actionFilter = url.searchParams.get('action');
    const projectFilter = url.searchParams.get('project');
    const dateFrom = url.searchParams.get('dateFrom');
    const dateTo = url.searchParams.get('dateTo');

    let entries = getAuditLog();

    if (userFilter) entries = entries.filter((e: { user: string }) => e.user === userFilter);
    if (actionFilter) entries = entries.filter((e: { action: string }) => e.action.startsWith(actionFilter));
    if (projectFilter) entries = entries.filter((e: { resource: string }) => e.resource.toLowerCase().includes(projectFilter.toLowerCase()));
    if (dateFrom) entries = entries.filter((e: { timestamp: string }) => e.timestamp >= dateFrom);
    if (dateTo) entries = entries.filter((e: { timestamp: string }) => e.timestamp <= dateTo);

    const total = entries.length;
    const start = (page - 1) * perPage;
    const items = entries.slice(start, start + perPage);

    return HttpResponse.json({ items, total, page, perPage });
  }),

  http.get('/api/v1/admin/audit-log/export', () => {
    return new HttpResponse(
      'timestamp,user,action,resource,detail\n2026-03-21T10:05:00Z,alex.chen@nk-sentinel.io,scan.completed,payment-service,"Scan #45 completed"',
      {
        headers: { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=audit-log.csv' },
      },
    );
  }),

  // ---------------------------------------------------------------------------
  // Plan 6 — Global search (D22 #43)
  // ---------------------------------------------------------------------------

  http.get('/api/v1/search', ({ request }) => {
    const url = new URL(request.url);
    const q = (url.searchParams.get('q') || '').toLowerCase();
    const type = url.searchParams.get('type');

    const results: Array<Record<string, unknown>> = [];

    if (!type || type === 'project') {
      const repos = [
        { type: 'project', id: 'repo-1', name: 'payment-service', group: 'nk-sentinel', provider: 'GitHub' },
        { type: 'project', id: 'repo-2', name: 'auth-api', group: 'nk-sentinel', provider: 'GitHub' },
        { type: 'project', id: 'repo-3', name: 'data-pipeline', group: 'nk-sentinel', provider: 'GitLab' },
        { type: 'project', id: 'repo-4', name: 'mobile-backend', group: 'nk-sentinel', provider: 'Bitbucket' },
      ];
      for (const r of repos) {
        if (r.name.includes(q) || r.group.includes(q)) results.push(r);
      }
    }

    if (!type || type === 'finding') {
      const findings = [
        { type: 'finding', id: 'f-001', repoId: 'repo-1', algorithm: null, file: 'SSLConfig.java', severity: 'critical', title: 'Certificate validation disabled' },
        { type: 'finding', id: 'f-002', repoId: 'repo-1', algorithm: 'MD5', file: 'hash.py', severity: 'high', title: 'MD5 hash function' },
        { type: 'finding', id: 'f-003', repoId: 'repo-1', algorithm: 'DES', file: 'CryptoUtil.java', severity: 'high', title: 'DES/ECB broken cipher' },
      ];
      for (const f of findings) {
        if (
          f.title.toLowerCase().includes(q) ||
          f.file.toLowerCase().includes(q) ||
          (f.algorithm?.toLowerCase().includes(q) ?? false)
        ) {
          results.push(f);
        }
      }
    }

    return HttpResponse.json({ results, total: results.length });
  }),

  // ---------------------------------------------------------------------------
  // Plan 5 — Remediation consent flow (D5)
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // D23 — PQC Migration Progress
  // ---------------------------------------------------------------------------

  http.get('/api/v1/portfolio/pqc-migration', () => {
    return HttpResponse.json({
      overview: {
        totalFindings: 120,
        vulnerable: 45,
        safe: 55,
        unknown: 20,
        percentVulnerable: 37.5,
        percentSafe: 45.83,
        percentUnknown: 16.67,
      },
      families: [
        { family: 'RSA', total: 40, vulnerable: 30, safe: 5, unknown: 5, percentMigrated: 12.5 },
        { family: 'ECDSA', total: 25, vulnerable: 10, safe: 12, unknown: 3, percentMigrated: 48.0 },
        { family: 'AES', total: 30, vulnerable: 0, safe: 28, unknown: 2, percentMigrated: 93.33 },
        { family: 'SHA-2', total: 15, vulnerable: 0, safe: 10, unknown: 5, percentMigrated: 66.67 },
        { family: 'DES', total: 5, vulnerable: 5, safe: 0, unknown: 0, percentMigrated: 0.0 },
        { family: 'MD5', total: 5, vulnerable: 0, safe: 0, unknown: 5, percentMigrated: 0.0 },
      ],
      laggingProjects: [
        { projectId: 'proj-001', projectName: 'payment-service', vulnerableCount: 18, totalCount: 25, percentVulnerable: 72.0 },
        { projectId: 'proj-002', projectName: 'auth-api', vulnerableCount: 12, totalCount: 30, percentVulnerable: 40.0 },
        { projectId: 'proj-003', projectName: 'data-pipeline', vulnerableCount: 8, totalCount: 35, percentVulnerable: 22.86 },
        { projectId: 'proj-004', projectName: 'mobile-backend', vulnerableCount: 7, totalCount: 30, percentVulnerable: 23.33 },
      ],
    });
  }),

  // ---------------------------------------------------------------------------
  // D23 — Certificate Tracker (paginated, filterable)
  // ---------------------------------------------------------------------------

  http.get('/api/v1/portfolio/certificates', ({ request }) => {
    const url = new URL(request.url);
    const statusColor = url.searchParams.get('status_color');
    const page = Number(url.searchParams.get('page') || '1');
    const perPage = Number(url.searchParams.get('per_page') || '25');

    const now = new Date();
    function computeStatus(expiryDate: string): { color: string; days: number } {
      const expiry = new Date(expiryDate);
      const days = Math.ceil((expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
      if (days < 0) return { color: 'black', days };
      if (days < 30) return { color: 'red', days };
      if (days <= 90) return { color: 'amber', days };
      return { color: 'green', days };
    }

    function daysFromNow(d: number): string {
      const dt = new Date();
      dt.setDate(dt.getDate() + d);
      return dt.toISOString();
    }

    const rawCerts = [
      { subject: 'api.payment.internal', issuer: 'Internal CA', notAfter: daysFromNow(-5), projectName: 'payment-service', projectId: 'proj-001', filePath: 'certs/api.pem' },
      { subject: 'auth.internal', issuer: 'Internal CA', notAfter: daysFromNow(3), projectName: 'auth-api', projectId: 'proj-002', filePath: 'certs/auth.pem' },
      { subject: '*.svc.cluster.local', issuer: 'Istio CA', notAfter: daysFromNow(12), projectName: 'data-pipeline', projectId: 'proj-003', filePath: 'k8s/tls-secret.yaml' },
      { subject: 'mobile.api.example.com', issuer: "Let's Encrypt R3", notAfter: daysFromNow(25), projectName: 'mobile-backend', projectId: 'proj-004', filePath: 'certs/mobile.pem' },
      { subject: 'grpc.payment.internal', issuer: 'Internal CA', notAfter: daysFromNow(45), projectName: 'payment-service', projectId: 'proj-001', filePath: 'certs/grpc.pem' },
      { subject: 'Root CA', issuer: 'Self-signed', notAfter: daysFromNow(180), projectName: 'payment-service', projectId: 'proj-001', filePath: 'certs/root-ca.pem' },
      { subject: 'kafka.internal', issuer: 'Internal CA', notAfter: daysFromNow(5), projectName: 'data-pipeline', projectId: 'proj-003', filePath: 'certs/kafka.pem' },
      { subject: 'redis.internal', issuer: 'Internal CA', notAfter: daysFromNow(200), projectName: 'auth-api', projectId: 'proj-002', filePath: 'certs/redis.pem' },
    ];

    let items = rawCerts.map((c, i) => {
      const { color, days } = computeStatus(c.notAfter);
      return {
        id: `cert-trk-${String(i + 1).padStart(3, '0')}`,
        subject: c.subject,
        issuer: c.issuer,
        notAfter: c.notAfter,
        statusColor: color,
        daysRemaining: days,
        projectName: c.projectName,
        projectId: c.projectId,
        filePath: c.filePath,
      };
    });

    if (statusColor) {
      items = items.filter((c) => c.statusColor === statusColor);
    }

    items.sort((a, b) => a.daysRemaining - b.daysRemaining);
    const total = items.length;
    const start = (page - 1) * perPage;
    const pageItems = items.slice(start, start + perPage);

    return HttpResponse.json({
      items: pageItems,
      total,
      page,
      perPage,
    });
  }),

  // ---------------------------------------------------------------------------
  // D4 — Group management
  // ---------------------------------------------------------------------------

  http.get('/api/v1/admin/groups', () => {
    return HttpResponse.json([
      {
        id: 'grp-001',
        name: 'Platform Engineering',
        description: 'Core platform services team',
        projectCount: 5,
        memberCount: 8,
        createdAt: '2026-01-15T10:00:00Z',
      },
      {
        id: 'grp-002',
        name: 'Security Team',
        description: 'Application security and compliance',
        projectCount: 3,
        memberCount: 4,
        createdAt: '2026-02-01T10:00:00Z',
      },
      {
        id: 'grp-003',
        name: 'Data Engineering',
        description: 'Data pipelines and analytics',
        projectCount: 2,
        memberCount: 6,
        createdAt: '2026-02-20T10:00:00Z',
      },
    ]);
  }),

  http.get('/api/v1/admin/groups/:groupId', ({ params }) => {
    const groupId = params['groupId'] as string;
    const groups: Record<string, object> = {
      'grp-001': {
        id: 'grp-001',
        name: 'Platform Engineering',
        description: 'Core platform services team',
        projectCount: 5,
        memberCount: 8,
        createdAt: '2026-01-15T10:00:00Z',
        members: [
          { email: 'alex.chen@nk-sentinel.io', name: 'Alex Chen', role: 'org-admin' },
          { email: 'sarah.kim@nk-sentinel.io', name: 'Sarah Kim', role: 'security-manager' },
          { email: 'bob@example.com', name: 'Bob Jones', role: 'developer' },
        ],
        projects: [
          { id: 'proj-001', name: 'payment-service' },
          { id: 'proj-002', name: 'auth-api' },
        ],
      },
      'grp-002': {
        id: 'grp-002',
        name: 'Security Team',
        description: 'Application security and compliance',
        projectCount: 3,
        memberCount: 4,
        createdAt: '2026-02-01T10:00:00Z',
        members: [
          { email: 'sarah.kim@nk-sentinel.io', name: 'Sarah Kim', role: 'security-manager' },
          { email: 'james.liu@nk-sentinel.io', name: 'James Liu', role: 'security-engineer' },
        ],
        projects: [
          { id: 'proj-001', name: 'payment-service' },
        ],
      },
      'grp-003': {
        id: 'grp-003',
        name: 'Data Engineering',
        description: 'Data pipelines and analytics',
        projectCount: 2,
        memberCount: 6,
        createdAt: '2026-02-20T10:00:00Z',
        members: [],
        projects: [
          { id: 'proj-003', name: 'data-pipeline' },
        ],
      },
    };
    const group = groups[groupId];
    if (!group) {
      return new HttpResponse(JSON.stringify({ error: 'Group not found' }), { status: 404 });
    }
    return HttpResponse.json(group);
  }),

  http.post('/api/v1/admin/groups', async ({ request }) => {
    const body = await request.json() as { name: string; description: string };
    return HttpResponse.json(
      {
        id: 'grp-' + Date.now().toString(),
        name: body.name,
        description: body.description,
        projectCount: 0,
        memberCount: 0,
        createdAt: new Date().toISOString(),
      },
      { status: 201 },
    );
  }),

  http.post('/api/v1/findings/:findingId/remediation', async ({ request, params }) => {
    const body = await request.json() as { consent: boolean; codeSnippet?: string };
    if (!body.consent) {
      return new HttpResponse(
        JSON.stringify({ detail: 'Consent required before sending code to LLM' }),
        { status: 400 },
      );
    }
    // Simulate delay
    await new Promise((resolve) => setTimeout(resolve, 1000));
    return HttpResponse.json({
      id: 'rem-' + Date.now().toString(),
      findingId: params['findingId'],
      confidence: 'high',
      provider: 'anthropic',
      explanation: 'AI-generated fix. Review carefully before applying.',
      diff: {
        originalCode: body.codeSnippet || '// original code',
        fixedCode: '// fixed code with secure alternative',
      },
      createdAt: new Date().toISOString(),
    });
  }),
];
