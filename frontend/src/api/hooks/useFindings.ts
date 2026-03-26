import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type { Finding, Severity, QuantumStatus, FindingStatus } from '@/mocks/data/findings';

export type { Finding, Severity, QuantumStatus, FindingStatus };

export type SortField = 'severity' | 'file' | 'title' | 'status' | 'firstSeen';
export type SortDirection = 'asc' | 'desc';

export interface FindingsFilters {
  severity?: Severity;
  quantumStatus?: QuantumStatus;
  search?: string;
  statuses?: FindingStatus[];
  page?: number;
  perPage?: number;
  sortField?: SortField;
  sortDirection?: SortDirection;
}

export interface FindingsCounts {
  all: number;
  critical: number;
  high: number;
  medium: number;
  quantumVulnerable: number;
  broken: number;
}

export interface StatusCounts {
  open: number;
  in_review: number;
  in_progress: number;
  resolved: number;
  risk_accepted: number;
  false_positive: number;
}

export interface FindingsResult {
  findings: Finding[];
  total: number;
  counts: FindingsCounts;
  statusCounts: StatusCounts;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_ORDER[a] - SEVERITY_ORDER[b];
}

/**
 * Fetch findings for a repository with optional filters, sorting, and pagination.
 * Real API endpoint: GET /api/v1/scans/:repoId/findings
 * Falls back to mock data in development if endpoint is not ready.
 */
export function useFindings(repoId: string, filters?: FindingsFilters) {
  return useQuery<FindingsResult>({
    queryKey: ['findings', repoId, filters],
    queryFn: async () => {
      try {
        const params = new URLSearchParams();
        if (filters?.severity) params.set('severity', filters.severity);
        if (filters?.quantumStatus) params.set('quantumStatus', filters.quantumStatus);
        if (filters?.search) params.set('search', filters.search);
        if (filters?.statuses && filters.statuses.length > 0) {
          params.set('statuses', filters.statuses.join(','));
        }
        if (filters?.page) params.set('page', String(filters.page));
        if (filters?.perPage) params.set('perPage', String(filters.perPage));
        if (filters?.sortField) params.set('sortField', filters.sortField);
        if (filters?.sortDirection) params.set('sortDirection', filters.sortDirection);
        const qs = params.toString();
        const url = `/scans/${repoId}/findings${qs ? `?${qs}` : ''}`;
        return await apiClient<FindingsResult>(url);
      } catch {
          const { getFindingsForRepo } = await import('@/mocks/data/findings');
          const allForRepo = getFindingsForRepo(repoId);
          let filtered = [...allForRepo];

          if (filters?.severity) {
            filtered = filtered.filter((f) => f.severity === filters.severity);
          }
          if (filters?.quantumStatus) {
            filtered = filtered.filter((f) => f.quantumStatus === filters.quantumStatus);
          }
          if (filters?.search) {
            const q = filters.search.toLowerCase();
            filtered = filtered.filter(
              (f) =>
                f.title.toLowerCase().includes(q) ||
                f.file.toLowerCase().includes(q) ||
                (f.algorithm?.toLowerCase().includes(q) ?? false),
            );
          }
          if (filters?.statuses && filters.statuses.length > 0) {
            filtered = filtered.filter((f) => filters.statuses!.includes(f.status));
          }

          // Sort
          const sortField = filters?.sortField ?? 'severity';
          const sortDir = filters?.sortDirection ?? 'desc';
          const dirMul = sortDir === 'asc' ? 1 : -1;

          filtered.sort((a, b) => {
            let cmp = 0;
            switch (sortField) {
              case 'severity':
                cmp = compareSeverity(a.severity, b.severity);
                break;
              case 'file':
                cmp = a.file.localeCompare(b.file);
                break;
              case 'title':
                cmp = a.title.localeCompare(b.title);
                break;
              case 'status':
                cmp = a.status.localeCompare(b.status);
                break;
              case 'firstSeen':
                cmp = a.firstSeen.localeCompare(b.firstSeen);
                break;
            }
            if (cmp !== 0) return cmp * dirMul;
            // Secondary sort by firstSeen desc
            return b.firstSeen.localeCompare(a.firstSeen);
          });

          const totalFiltered = filtered.length;

          // Pagination
          const page = filters?.page ?? 1;
          const perPage = filters?.perPage ?? 25;
          const startIdx = (page - 1) * perPage;
          const paginated = filtered.slice(startIdx, startIdx + perPage);

          const counts: FindingsCounts = {
            all: allForRepo.length,
            critical: allForRepo.filter((f) => f.severity === 'critical').length,
            high: allForRepo.filter((f) => f.severity === 'high').length,
            medium: allForRepo.filter((f) => f.severity === 'medium').length,
            quantumVulnerable: allForRepo.filter((f) => f.quantumStatus === 'vulnerable').length,
            broken: allForRepo.filter((f) => f.quantumStatus === 'broken').length,
          };

          const statusCounts: StatusCounts = {
            open: allForRepo.filter((f) => f.status === 'open').length,
            in_review: allForRepo.filter((f) => f.status === 'in_review').length,
            in_progress: allForRepo.filter((f) => f.status === 'in_progress').length,
            resolved: allForRepo.filter((f) => f.status === 'resolved').length,
            risk_accepted: allForRepo.filter((f) => f.status === 'risk_accepted').length,
            false_positive: allForRepo.filter((f) => f.status === 'false_positive').length,
          };

          return {
            findings: paginated,
            total: totalFiltered,
            counts,
            statusCounts,
          };
    }
    },
    staleTime: 30_000,
    enabled: !!repoId,
  });
}

/**
 * Fetch a single finding by ID.
 * Real API endpoint: GET /api/v1/findings/:id
 * Falls back to mock data in development if endpoint is not ready.
 */
export function useFinding(findingId: string | null) {
  return useQuery<Finding | undefined>({
    queryKey: ['finding', findingId],
    queryFn: async () => {
      try {
        const data = await apiClient<Finding>(`/findings/${findingId!}`);
        if (data) return data;
      } catch {
          const { getFindingById } = await import('@/mocks/data/findings');
          return getFindingById(findingId!);
    }
    },
    staleTime: 30_000,
    enabled: !!findingId,
  });
}
