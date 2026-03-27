import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import { useToast } from '@/lib/use-toast.ts';
import type { Role } from '@/lib/roles.ts';

export interface ManagedUser {
  id: string;
  name: string;
  email: string;
  role: Role;
  authSource: string;
  lastActive: string;
  status: 'active' | 'invited' | 'disabled';
  groups: { id: string; name: string }[];
  apiKeyCount: number;
  createdAt: string;
}

interface UsersResponse {
  items: ManagedUser[];
  total: number;
  page: number;
  perPage: number;
}

interface ChangeRoleParams {
  userId: string;
  role: Role;
}

interface InviteUserParams {
  email: string;
  role: Role;
}

interface DirectAddUserParams {
  email: string;
  name: string;
  tempPassword: string;
  role: Role;
  groupIds: string[];
}

/**
 * Fetch paginated user list with search.
 * Real API endpoint: GET /api/v1/admin/users
 */
export function useUsers(page: number, perPage: number, search: string) {
  return useQuery({
    queryKey: ['admin', 'users', page, perPage, search],
    queryFn: async () => {
      const params = new URLSearchParams({
        page: String(page),
        perPage: String(perPage),
      });
      if (search) params.set('search', search);
      const data = await apiClient<UsersResponse>(`/admin/users?${params.toString()}`);
      return data;
    },
    staleTime: 15_000,
  });
}

/**
 * Change a user's role.
 * Real API endpoint: PATCH /api/v1/admin/users/:userId/role
 */
export function useChangeRole() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  return useMutation({
    mutationFn: async ({ userId, role }: ChangeRoleParams) => {
      return apiClient(`/admin/users/${userId}/role`, {
        method: 'PATCH',
        body: { role },
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['admin', 'users'] });
      toast({ title: 'Role updated', variant: 'success' });
    },
    onError: (err) => {
      toast({ title: 'Failed to update role', description: err.message, variant: 'error' });
    },
  });
}

/**
 * Disable a user.
 * Real API endpoint: POST /api/v1/admin/users/:userId/disable
 */
export function useDisableUser() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  return useMutation({
    mutationFn: async (userId: string) => {
      return apiClient(`/admin/users/${userId}/disable`, {
        method: 'POST',
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['admin', 'users'] });
      toast({ title: 'User disabled', variant: 'success' });
    },
    onError: (err) => {
      toast({ title: 'Failed to disable user', description: err.message, variant: 'error' });
    },
  });
}

/**
 * Re-enable a disabled user.
 * Real API endpoint: POST /api/v1/admin/users/:userId/enable
 */
export function useEnableUser() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  return useMutation({
    mutationFn: async (userId: string) => {
      return apiClient(`/admin/users/${userId}/enable`, {
        method: 'POST',
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['admin', 'users'] });
      toast({ title: 'User re-enabled', variant: 'success' });
    },
    onError: (err) => {
      toast({ title: 'Failed to enable user', description: err.message, variant: 'error' });
    },
  });
}

/**
 * Delete a disabled user (soft-delete).
 * Real API endpoint: DELETE /api/v1/admin/users/:userId
 */
export function useDeleteUser() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  return useMutation({
    mutationFn: async (userId: string) => {
      return apiClient(`/admin/users/${userId}`, {
        method: 'DELETE',
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['admin', 'users'] });
      toast({ title: 'User deleted', variant: 'success' });
    },
    onError: (err) => {
      toast({ title: 'Failed to delete user', description: err.message, variant: 'error' });
    },
  });
}

/**
 * Invite a user via email.
 * Real API endpoint: POST /api/v1/admin/users/invite
 */
export function useInviteUser() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  return useMutation({
    mutationFn: async (params: InviteUserParams) => {
      return apiClient('/admin/users/invite', {
        method: 'POST',
        body: params,
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['admin', 'users'] });
      toast({ title: 'Invite sent', variant: 'success' });
    },
    onError: (err) => {
      toast({ title: 'Failed to send invite', description: err.message, variant: 'error' });
    },
  });
}

/**
 * Directly add a user (no invite email).
 * Real API endpoint: POST /api/v1/admin/users
 */
export function useDirectAddUser() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  return useMutation({
    mutationFn: async (params: DirectAddUserParams) => {
      return apiClient('/admin/users', {
        method: 'POST',
        body: params,
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['admin', 'users'] });
      toast({ title: 'User added', variant: 'success' });
    },
    onError: (err) => {
      toast({ title: 'Failed to add user', description: err.message, variant: 'error' });
    },
  });
}
