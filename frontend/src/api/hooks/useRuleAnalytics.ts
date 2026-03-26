import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type TimeWindow = '30d' | '90d' | '180d' | '1y' | 'all';

export interface TrendPoint {
  scanId: string;
  count: number;
  scannedAt: string;
}

export interface RuleAnalyticsData {
  ruleId: string;
  totalFindings: number;
  activeFindings: number;
  fpRate: number;
  raRate: number;
  fixRate: number;
  mttrSeconds: number | null;
  trend: TrendPoint[];
  timeWindow: string;
}

export interface RuleSummary {
  ruleId: string;
  totalFindings: number;
  fpRate: number;
  fixRate: number;
  mttrSeconds: number | null;
  warning: boolean;
}

/**
 * Classify a rule's signal quality based on FP rate and fix rate.
 * Quadrant mapping:
 *   - Low FP + High fix  -> "Valuable"
 *   - High FP + High fix -> "Noisy"
 *   - Low FP + Low fix   -> "Ignored"
 *   - High FP + Low fix  -> "Pure noise"
 */
export function classifySignalQuality(fpRate: number, fixRate: number): string {
  const highFP = fpRate > 50;
  const lowFix = fixRate < 10;

  if (!highFP && !lowFix) return 'Valuable';
  if (highFP && !lowFix) return 'Noisy';
  if (!highFP && lowFix) return 'Ignored';
  return 'Pure noise';
}

/**
 * Format MTTR seconds into a human-readable string.
 */
export function formatMTTR(seconds: number | null): string {
  if (seconds === null || seconds === 0) return 'N/A';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  if (days > 0) return `${String(days)}d ${String(hours)}h`;
  if (hours > 0) return `${String(hours)}h`;
  const minutes = Math.floor(seconds / 60);
  return `${String(minutes)}m`;
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

/**
 * Fetch analytics for a single rule.
 * Real API endpoint: GET /api/v1/admin/rules/:ruleId/analytics?time_window=90d
 */
export function useRuleAnalytics(ruleId: string, timeWindow: TimeWindow = '90d') {
  return useQuery<RuleAnalyticsData>({
    queryKey: ['rule-analytics', ruleId, timeWindow],
    queryFn: async () => {
      return apiClient<RuleAnalyticsData>(
        `/admin/rules/${ruleId}/analytics?time_window=${timeWindow}`,
      );
    },
    staleTime: 60_000,
    enabled: !!ruleId,
  });
}

/**
 * Fetch analytics summary for all rules.
 * Real API endpoint: GET /api/v1/admin/rules/summary?time_window=90d
 */
export function useRulesSummary(timeWindow: TimeWindow = '90d') {
  return useQuery<RuleSummary[]>({
    queryKey: ['rules-summary', timeWindow],
    queryFn: async () => {
      return apiClient<RuleSummary[]>(
        `/admin/rules/summary?time_window=${timeWindow}`,
      );
    },
    staleTime: 60_000,
  });
}
