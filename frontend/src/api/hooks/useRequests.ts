import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import { useToast } from '@/lib/use-toast.ts';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type RequestType = 'false_positive' | 'risk_accepted';
export type RequestStatus = 'pending' | 'approved' | 'rejected';

export type ReasonCategory =
  | 'compensating_control'
  | 'low_impact'
  | 'migration_planned'
  | 'business_exception';

export interface ReviewRequest {
  id: string;
  findingId: string;
  findingSummary: string;
  findingSeverity: string;
  requester: string;
  type: RequestType;
  justification: string;
  reasonCategory?: ReasonCategory;
  reviewDate?: string;
  status: RequestStatus;
  createdAt: string;
}

export interface RequestsResult {
  items: ReviewRequest[];
  total: number;
}

export interface CreateRequestInput {
  findingId: string;
  type: RequestType;
  justification: string;
  reasonCategory?: ReasonCategory;
  reviewDate?: string;
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

export function useRequests(page: number = 1, perPage: number = 25) {
  return useQuery<RequestsResult>({
    queryKey: ['requests', page, perPage],
    queryFn: async () => {
      return apiClient<RequestsResult>(
        `/requests?page=${String(page)}&perPage=${String(perPage)}`,
      );
    },
    staleTime: 15_000,
  });
}

export function useCreateRequest() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (input: CreateRequestInput) => {
      return apiClient(`/findings/${input.findingId}/request`, {
        method: 'POST',
        body: {
          type: input.type,
          justification: input.justification,
          reasonCategory: input.reasonCategory,
          reviewDate: input.reviewDate,
        },
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['requests'] });
      void queryClient.invalidateQueries({ queryKey: ['findings'] });
      toast({ title: 'Request submitted', variant: 'success' });
    },
    onError: (err: Error) => {
      toast({
        title: 'Failed to submit request',
        description: err.message,
        variant: 'error',
      });
    },
  });
}

export function useApproveRequest() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: async (requestId: string) => {
      return apiClient(`/requests/${requestId}/approve`, {
        method: 'POST',
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['requests'] });
      void queryClient.invalidateQueries({ queryKey: ['findings'] });
      toast({ title: 'Request approved', variant: 'success' });
    },
    onError: (err: Error) => {
      toast({
        title: 'Failed to approve request',
        description: err.message,
        variant: 'error',
      });
    },
  });
}

export function useRejectRequest() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  return useMutation({
    mutationFn: async ({ requestId, reason }: { requestId: string; reason: string }) => {
      return apiClient(`/requests/${requestId}/reject`, {
        method: 'POST',
        body: { reason },
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['requests'] });
      void queryClient.invalidateQueries({ queryKey: ['findings'] });
      toast({ title: 'Request rejected', variant: 'success' });
    },
    onError: (err: Error) => {
      toast({
        title: 'Failed to reject request',
        description: err.message,
        variant: 'error',
      });
    },
  });
}
