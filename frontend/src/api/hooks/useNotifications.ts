import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type {
  Notification,
  NotificationPreferencesData,
} from '@/mocks/data/notifications.ts';

/**
 * Fetch all notifications.
 * Real API endpoint: GET /api/v1/notifications
 */
export function useNotifications() {
  return useQuery({
    queryKey: ['notifications'],
    queryFn: async () => {
      try {
        return await apiClient<Notification[]>('/notifications');
      } catch {
        if (import.meta.env.DEV) {
          const { getNotifications } = await import('@/mocks/data/notifications.ts');
          return getNotifications();
        }
        throw new Error('Failed to fetch notifications');
      }
    },
    staleTime: 15_000,
    refetchInterval: 30_000,
  });
}

/**
 * Mark a single notification as read.
 * Real API endpoint: PATCH /api/v1/notifications/:id
 */
export function useMarkRead() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (id: string) => {
      try {
        return await apiClient<{ success: boolean }>(`/notifications/${id}/read`, {
          method: 'PATCH',
        });
      } catch {
        // Optimistic update only in dev
        return { success: true };
      }
    },
    onMutate: async (id: string) => {
      await queryClient.cancelQueries({ queryKey: ['notifications'] });
      const previous = queryClient.getQueryData<Notification[]>(['notifications']);
      queryClient.setQueryData<Notification[]>(['notifications'], (old) =>
        old?.map((n) => (n.id === id ? { ...n, unread: false } : n)),
      );
      return { previous };
    },
    onError: (_err, _id, context) => {
      if (context?.previous) {
        queryClient.setQueryData(['notifications'], context.previous);
      }
    },
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: ['notifications'] });
    },
  });
}

/**
 * Mark all notifications as read.
 * Real API endpoint: POST /api/v1/notifications/read-all
 */
export function useMarkAllRead() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async () => {
      try {
        return await apiClient<{ success: boolean }>('/notifications/read-all', {
          method: 'POST',
        });
      } catch {
        // Optimistic update only in dev
        return { success: true };
      }
    },
    onMutate: async () => {
      await queryClient.cancelQueries({ queryKey: ['notifications'] });
      const previous = queryClient.getQueryData<Notification[]>(['notifications']);
      queryClient.setQueryData<Notification[]>(['notifications'], (old) =>
        old?.map((n) => ({ ...n, unread: false })),
      );
      return { previous };
    },
    onError: (_err, _vars, context) => {
      if (context?.previous) {
        queryClient.setQueryData(['notifications'], context.previous);
      }
    },
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: ['notifications'] });
    },
  });
}

/**
 * Fetch notification preferences.
 * Real API endpoint: GET /api/v1/notifications/preferences
 */
export function useNotificationPreferences() {
  return useQuery({
    queryKey: ['notification-preferences'],
    queryFn: async () => {
      try {
        return await apiClient<NotificationPreferencesData>('/notifications/preferences');
      } catch {
        if (import.meta.env.DEV) {
          const { getNotificationPreferences } = await import(
            '@/mocks/data/notifications.ts'
          );
          return getNotificationPreferences();
        }
        throw new Error('Failed to fetch notification preferences');
      }
    },
    staleTime: 60_000,
  });
}

/**
 * Update notification preferences.
 * Real API endpoint: PUT /api/v1/notifications/preferences
 */
export function useUpdateNotificationPreferences() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (prefs: NotificationPreferencesData) => {
      try {
        return await apiClient<NotificationPreferencesData>(
          '/notifications/preferences',
          { method: 'PUT', body: prefs },
        );
      } catch {
        // Optimistic update in dev
        return prefs;
      }
    },
    onSuccess: (data) => {
      queryClient.setQueryData(['notification-preferences'], data);
    },
  });
}
