import { http, HttpResponse } from 'msw';
import {
  MOCK_REPOSITORIES,
  MOCK_REPOSITORY_DETAILS,
} from './data/repositories.ts';
import { getScansForRepo, getScanDetail } from './data/scans.ts';

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

  http.get('/api/v1/repos/:repoId/scans', ({ params }) => {
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
];
