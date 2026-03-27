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

  // Admin: integrations
  http.get('/api/v1/admin/integrations', () => {
    return HttpResponse.json(getIntegrations());
  }),

  // Admin: audit log
  http.get('/api/v1/admin/audit-log', () => {
    return HttpResponse.json(getAuditLog());
  }),

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
  http.get('/api/v1/findings/:findingId/history', ({ params, request }) => {
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
  http.post('/api/v1/scans/:scanId/rerun', ({ params }) => {
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

  http.post('/api/v1/admin/registries/:registryId/test', ({ params }) => {
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

  http.put('/api/v1/admin/users/:userId/reset-password', ({ params }) => {
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
          scopes: ['scan:read', 'scan:write'],
          createdAt: '2026-03-15T10:00:00Z',
          expiresAt: null,
          lastUsedAt: '2026-03-27T08:00:00Z',
          revokedAt: null,
        },
      ],
      total: 1,
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
];
