import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import { useToast } from '@/lib/use-toast.ts';

export interface Group {
  id: string;
  name: string;
  description: string;
  projectCount: number;
  memberCount: number;
  createdAt: string;
}

export interface GroupDetail extends Group {
  members: Array<{ email: string; name: string; role: string }>;
  projects: Array<{ id: string; name: string }>;
}

interface CreateGroupParams {
  name: string;
  description: string;
}

/**
 * Fetch all groups for the org.
 * Real API endpoint: GET /api/v1/admin/groups
 */
export function useGroups() {
  return useQuery({
    queryKey: ['groups'],
    queryFn: async () => {
      const data = await apiClient<Group[] | { items: Group[] }>('/admin/groups');
      return Array.isArray(data) ? data : (data?.items ?? []);
    },
    staleTime: 30_000,
  });
}

/**
 * Fetch a single group's detail.
 * Real API endpoint: GET /api/v1/admin/groups/:groupId
 */
export function useGroupDetail(groupId: string | null) {
  return useQuery({
    queryKey: ['groups', groupId],
    queryFn: async () => {
      if (!groupId) return null;
      return apiClient<GroupDetail>(`/admin/groups/${groupId}`);
    },
    enabled: !!groupId,
    staleTime: 30_000,
  });
}

/**
 * Create a new group.
 * Real API endpoint: POST /api/v1/admin/groups
 */
export function useCreateGroup() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  return useMutation({
    mutationFn: async (params: CreateGroupParams) => {
      return apiClient<Group>('/admin/groups', {
        method: 'POST',
        body: params,
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['groups'] });
      toast({ title: 'Group created', variant: 'success' });
    },
    onError: (err) => {
      toast({ title: 'Failed to create group', description: err.message, variant: 'error' });
    },
  });
}
