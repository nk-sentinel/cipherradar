import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';

export interface CertificateEntry {
  id: string;
  subject: string;
  issuer: string;
  notAfter: string;
  statusColor: 'green' | 'amber' | 'red' | 'black';
  daysRemaining: number;
  projectName: string;
  projectId: string;
  filePath: string;
}

export interface CertificateTrackerResponse {
  items: CertificateEntry[];
  total: number;
  page: number;
  perPage: number;
}

interface CertificateTrackerFilters {
  statusColor?: string | null;
  projectId?: string | null;
  page?: number;
  perPage?: number;
}

/**
 * Fetch certificate tracker data from GET /api/v1/portfolio/certificates.
 * Supports filtering by status color, project, and pagination.
 */
export function useCertificateTracker(filters: CertificateTrackerFilters = {}) {
  const { statusColor, projectId, page = 1, perPage = 25 } = filters;

  return useQuery<CertificateTrackerResponse>({
    queryKey: ['certificate-tracker', statusColor, projectId, page, perPage],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (statusColor) params.set('status_color', statusColor);
      if (projectId) params.set('project_id', projectId);
      params.set('page', String(page));
      params.set('per_page', String(perPage));

      const qs = params.toString();
      try {
        const data = await apiClient<CertificateTrackerResponse>(
          `/portfolio/certificates${qs ? `?${qs}` : ''}`,
        );
        if (data && Array.isArray(data.items)) return data;
      } catch (err) {
        if (!import.meta.env.DEV) throw err;
        console.warn('[CipherRadar] API unavailable, using mock data for certificate tracker');
      }
      if (!import.meta.env.DEV) {
        throw new Error('Certificate tracker API unavailable');
      }
      const { getCertificates } = await import('@/mocks/data/certificates.ts');
      const certs = getCertificates();
      // Convert mock data to tracker response shape
      const now = new Date();
      const mapped: CertificateEntry[] = certs.map((c) => {
        const expiry = new Date(c.expiryDate);
        const days = Math.ceil((expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
        let color: CertificateEntry['statusColor'] = 'green';
        if (days < 0) color = 'black';
        else if (days < 30) color = 'red';
        else if (days <= 90) color = 'amber';
        return {
          id: c.id,
          subject: c.commonName,
          issuer: c.issuer,
          notAfter: c.expiryDate,
          statusColor: color,
          daysRemaining: days,
          projectName: c.repository,
          projectId: c.id,
          filePath: c.file,
        };
      });
      let filtered = mapped;
      if (statusColor) {
        filtered = filtered.filter((e) => e.statusColor === statusColor);
      }
      filtered.sort((a, b) => a.daysRemaining - b.daysRemaining);
      const total = filtered.length;
      const start = (page - 1) * perPage;
      const items = filtered.slice(start, start + perPage);
      return { items, total, page, perPage };
    },
    staleTime: 30_000,
  });
}
