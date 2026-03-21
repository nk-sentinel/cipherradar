import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type {
  OrgSettings,
  OrgUser,
  Integration,
  AuditLogEntry,
} from '@/mocks/data/admin.ts';

/**
 * Fetch org settings.
 * Real API endpoint: GET /api/v1/admin/settings
 */
export function useOrgSettings() {
  return useQuery({
    queryKey: ['admin', 'org-settings'],
    queryFn: async () => {
      try {
        const data = await apiClient<OrgSettings>('/admin/settings');
        if (data) return data;
      } catch {
          const { getOrgSettings } = await import('@/mocks/data/admin.ts');
          return getOrgSettings();
    }
    },
    staleTime: 60_000,
  });
}

/**
 * Fetch org users list.
 * Real API endpoint: GET /api/v1/admin/users
 */
export function useOrgUsers() {
  return useQuery({
    queryKey: ['admin', 'users'],
    queryFn: async () => {
      try {
        const data = await apiClient<OrgUser[]>('/admin/users');
        if (data) return data;
      } catch {
          const { getOrgUsers } = await import('@/mocks/data/admin.ts');
          return getOrgUsers();
    }
    },
    staleTime: 30_000,
  });
}

/**
 * Fetch integrations list.
 * Real API endpoint: GET /api/v1/admin/integrations
 */
export function useIntegrations() {
  return useQuery({
    queryKey: ['admin', 'integrations'],
    queryFn: async () => {
      try {
        const data = await apiClient<Integration[]>('/admin/integrations');
        if (data) return data;
      } catch {
          const { getIntegrations } = await import('@/mocks/data/admin.ts');
          return getIntegrations();
    }
    },
    staleTime: 60_000,
  });
}

/**
 * Fetch audit log entries.
 * Real API endpoint: GET /api/v1/admin/audit-log
 */
export function useAuditLog() {
  return useQuery({
    queryKey: ['admin', 'audit-log'],
    queryFn: async () => {
      try {
        const data = await apiClient<AuditLogEntry[]>('/admin/audit-log');
        if (data) return data;
      } catch {
          const { getAuditLog } = await import('@/mocks/data/admin.ts');
          return getAuditLog();
    }
    },
    staleTime: 15_000,
  });
}
