import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../client';
import { useToast } from '@/lib/use-toast';

export interface Registry {
  id: string;
  name: string;
  registryType: string;
  url: string;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface CreateRegistryParams {
  name: string;
  registryType: string;
  url: string;
  authMethod?: string;
  credentials?: Record<string, string>;
}

export interface UpdateRegistryParams extends CreateRegistryParams {
  id: string;
}

interface TestConnectionResult {
  success: boolean;
  message: string;
  latencyMs: number;
}

export function useRegistries() {
  return useQuery<Registry[]>({
    queryKey: ['registries'],
    queryFn: async (): Promise<Registry[]> => {
      const data = await apiClient<Registry[] | { items: Registry[] }>('/admin/registries');
      return Array.isArray(data) ? data : (data.items ?? []);
    },
    staleTime: 60_000,
  });
}

export function useCreateRegistry() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (params: CreateRegistryParams) => {
      return apiClient('/admin/registries', {
        method: 'POST',
        body: params,
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['registries'] });
      toast({ title: 'Registry added', variant: 'success' });
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to add registry', description: err.message, variant: 'error' });
    },
  });
}

export function useUpdateRegistry() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (params: UpdateRegistryParams) => {
      return apiClient(`/admin/registries/${params.id}`, {
        method: 'PUT',
        body: params,
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['registries'] });
      toast({ title: 'Registry updated', variant: 'success' });
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to update registry', description: err.message, variant: 'error' });
    },
  });
}

export function useDeleteRegistry() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (id: string) => {
      return apiClient(`/admin/registries/${id}`, { method: 'DELETE' });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['registries'] });
      toast({ title: 'Registry deleted', variant: 'success' });
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to delete registry', description: err.message, variant: 'error' });
    },
  });
}

export function useTestConnection() {
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (id: string): Promise<TestConnectionResult> => {
      return apiClient<TestConnectionResult>(`/admin/registries/${id}/test`, {
        method: 'POST',
      });
    },
    onSuccess: (result: TestConnectionResult) => {
      if (result.success) {
        toast({ title: 'Connection successful', description: `${String(result.latencyMs)}ms`, variant: 'success' });
      } else {
        toast({ title: 'Connection failed', description: result.message, variant: 'error' });
      }
    },
    onError: (err: Error) => {
      toast({ title: 'Connection test failed', description: err.message, variant: 'error' });
    },
  });
}
