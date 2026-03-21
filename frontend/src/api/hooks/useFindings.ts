import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type { Finding, Severity, QuantumStatus } from '@/mocks/data/findings';

export type { Finding, Severity, QuantumStatus };

export interface FindingsFilters {
  severity?: Severity;
  quantumStatus?: QuantumStatus;
  search?: string;
}

export interface FindingsCounts {
  all: number;
  critical: number;
  high: number;
  medium: number;
  quantumVulnerable: number;
  broken: number;
}

export interface FindingsResult {
  findings: Finding[];
  total: number;
  counts: FindingsCounts;
}

/**
 * Fetch findings for a repository with optional filters.
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

          const counts: FindingsCounts = {
            all: allForRepo.length,
            critical: allForRepo.filter((f) => f.severity === 'critical').length,
            high: allForRepo.filter((f) => f.severity === 'high').length,
            medium: allForRepo.filter((f) => f.severity === 'medium').length,
            quantumVulnerable: allForRepo.filter((f) => f.quantumStatus === 'vulnerable').length,
            broken: allForRepo.filter((f) => f.quantumStatus === 'broken').length,
          };

          return {
            findings: filtered,
            total: filtered.length,
            counts,
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
        return await apiClient<Finding>(`/findings/${findingId!}`);
      } catch {
          const { getFindingById } = await import('@/mocks/data/findings');
          return getFindingById(findingId!);
    }
    },
    staleTime: 30_000,
    enabled: !!findingId,
  });
}
