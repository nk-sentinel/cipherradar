import { useQuery } from '@tanstack/react-query';
import {
  getFindingsForRepo,
  getFindingById,
  type Finding,
  type Severity,
  type QuantumStatus,
} from '@/mocks/data/findings';

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
 * Uses mock data in development; will switch to apiClient once backend is ready.
 */
export function useFindings(repoId: string, filters?: FindingsFilters) {
  return useQuery<FindingsResult>({
    queryKey: ['findings', repoId, filters],
    queryFn: async () => {
      // Simulate network latency
      await new Promise((r) => setTimeout(r, 100));

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
    },
    staleTime: 30_000,
    enabled: !!repoId,
  });
}

/**
 * Fetch a single finding by ID.
 * Uses mock data in development; will switch to apiClient once backend is ready.
 */
export function useFinding(findingId: string | null) {
  return useQuery<Finding | undefined>({
    queryKey: ['finding', findingId],
    queryFn: async () => {
      await new Promise((r) => setTimeout(r, 50));
      return getFindingById(findingId!);
    },
    staleTime: 30_000,
    enabled: !!findingId,
  });
}
