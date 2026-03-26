import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import { useToast } from '@/lib/use-toast.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type JiraScopeType = 'group' | 'project';

export interface JiraPriorityMapping {
  critical: string;
  high: string;
  medium: string;
  low: string;
}

export interface JiraConfig {
  id: string;
  jiraProjectKey: string;
  defaultIssueType: string;
  priorityMapping: Partial<JiraPriorityMapping>;
  customFields: Record<string, unknown>;
  defaultAssignee: string | null;
  labels: string[];
  scope: JiraScopeType;
}

export interface JiraConfigInput {
  jiraProjectKey: string;
  defaultIssueType: string;
  priorityMapping: JiraPriorityMapping;
  defaultAssignee: string;
  labels: string[];
}

export interface CreateJiraIssueInput {
  findingId: string;
  summary: string;
  description: string;
  priority: string;
  issueType: string;
  labels: string[];
}

export interface JiraIssueResult {
  issueKey: string;
  issueUrl: string;
  summary: string;
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

/**
 * Fetch Jira configuration for a group or project scope.
 * Real API endpoint: GET /api/v1/groups/:id/jira-config or GET /api/v1/projects/:id/jira-config
 */
export function useJiraConfig(scopeType: JiraScopeType, scopeId: string) {
  const prefix = scopeType === 'group' ? 'groups' : 'projects';
  return useQuery<JiraConfig | null>({
    queryKey: ['jira-config', scopeType, scopeId],
    queryFn: async () => {
      try {
        return await apiClient<JiraConfig>(`/${prefix}/${scopeId}/jira-config`);
      } catch {
        return null;
      }
    },
    staleTime: 60_000,
    enabled: !!scopeId,
  });
}

/**
 * Save (create or update) Jira configuration for a group or project.
 * Real API endpoint: PUT /api/v1/groups/:id/jira-config or PUT /api/v1/projects/:id/jira-config
 */
export function useSaveJiraConfig(scopeType: JiraScopeType, scopeId: string) {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const prefix = scopeType === 'group' ? 'groups' : 'projects';

  return useMutation({
    mutationFn: async (config: JiraConfigInput) => {
      return apiClient<JiraConfig>(`/${prefix}/${scopeId}/jira-config`, {
        method: 'PUT',
        body: config,
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['jira-config', scopeType, scopeId] });
      toast({ title: 'Jira configuration saved', variant: 'success' });
    },
    onError: (err: Error) => {
      toast({
        title: 'Failed to save Jira configuration',
        description: err.message,
        variant: 'error',
      });
    },
  });
}

/**
 * Create a Jira issue for a finding.
 * Real API endpoint: POST /api/v1/findings/:findingId/jira
 */
export function useCreateJiraIssue() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (input: CreateJiraIssueInput) => {
      return apiClient<JiraIssueResult>(`/findings/${input.findingId}/jira`, {
        method: 'POST',
        body: {
          summary: input.summary,
          description: input.description,
          priority: input.priority,
          issueType: input.issueType,
          labels: input.labels,
        },
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['findings'] });
      toast({ title: 'Jira issue created', variant: 'success' });
    },
    onError: (err: Error) => {
      toast({
        title: 'Failed to create Jira issue',
        description: err.message,
        variant: 'error',
      });
    },
  });
}
