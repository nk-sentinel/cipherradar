import { useQuery, useMutation } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type { AuditLogEntry } from '@/mocks/data/admin.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AuditLogFilters {
  page: number;
  perPage: number;
  user?: string;
  action?: string;
  project?: string;
  dateFrom?: string;
  dateTo?: string;
}

export interface PaginatedAuditLog {
  items: AuditLogEntry[];
  total: number;
  page: number;
  perPage: number;
}

export type DatePreset = 'today' | '7d' | '30d' | '90d' | 'custom';

export const DATE_PRESETS: { value: DatePreset; label: string }[] = [
  { value: 'today', label: 'Today' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: '90d', label: 'Last 90 days' },
  { value: 'custom', label: 'Custom range' },
];

/**
 * Convert a preset to a date range (ISO strings).
 */
export function presetToDateRange(preset: DatePreset): { from: string; to: string } | null {
  if (preset === 'custom') return null;
  const now = new Date();
  const to = now.toISOString();
  const from = new Date(now);
  switch (preset) {
    case 'today':
      from.setHours(0, 0, 0, 0);
      break;
    case '7d':
      from.setDate(from.getDate() - 7);
      break;
    case '30d':
      from.setDate(from.getDate() - 30);
      break;
    case '90d':
      from.setDate(from.getDate() - 90);
      break;
  }
  return { from: from.toISOString(), to };
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

/**
 * Fetch paginated audit log with server-side filters.
 * Real API endpoint: GET /api/v1/admin/audit-log?page=...&perPage=...&user=...&action=...
 */
export function useAuditLogPaginated(filters: AuditLogFilters) {
  const params = new URLSearchParams();
  params.set('page', String(filters.page));
  params.set('perPage', String(filters.perPage));
  if (filters.user) params.set('user', filters.user);
  if (filters.action) params.set('action', filters.action);
  if (filters.project) params.set('project', filters.project);
  if (filters.dateFrom) params.set('dateFrom', filters.dateFrom);
  if (filters.dateTo) params.set('dateTo', filters.dateTo);

  return useQuery<PaginatedAuditLog>({
    queryKey: ['admin', 'audit-log', filters],
    queryFn: async () => {
      return apiClient<PaginatedAuditLog>(`/admin/audit-log?${params.toString()}`);
    },
    staleTime: 15_000,
  });
}

/**
 * Export audit log as CSV.
 * Real API endpoint: GET /api/v1/admin/audit-log/export
 */
export function useExportAuditLog() {
  return useMutation<Blob, Error, AuditLogFilters>({
    mutationFn: async (filters) => {
      const params = new URLSearchParams();
      if (filters.user) params.set('user', filters.user);
      if (filters.action) params.set('action', filters.action);
      if (filters.project) params.set('project', filters.project);
      if (filters.dateFrom) params.set('dateFrom', filters.dateFrom);
      if (filters.dateTo) params.set('dateTo', filters.dateTo);

      const token = sessionStorage.getItem('cipherradar-token');
      const response = await fetch(`/api/v1/admin/audit-log/export?${params.toString()}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!response.ok) throw new Error('Export failed');
      return response.blob();
    },
  });
}
