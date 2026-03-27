import { useMutation } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import { useToast } from '@/lib/use-toast.ts';

interface ChangePasswordParams {
  currentPassword: string;
  newPassword: string;
}

/**
 * Change the current user's password.
 * Real API endpoint: PUT /api/v1/auth/password
 */
export function useChangePassword() {
  const { toast } = useToast();
  return useMutation({
    mutationFn: async (params: ChangePasswordParams) => {
      return apiClient('/auth/password', {
        method: 'PUT',
        body: params,
      });
    },
    onSuccess: () => {
      toast({ title: 'Password changed successfully', variant: 'success' });
    },
    onError: (err) => {
      toast({ title: 'Failed to change password', description: err.message, variant: 'error' });
    },
  });
}
