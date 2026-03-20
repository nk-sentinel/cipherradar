import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../client.ts';
import type { Certificate } from '@/mocks/data/certificates.ts';

/**
 * Fetch all certificates for the calendar view.
 * Real API endpoint: GET /api/v1/certificates
 */
export function useCertificates() {
  return useQuery({
    queryKey: ['certificates'],
    queryFn: () => apiClient<Certificate[]>('/certificates'),
    staleTime: 60_000,
  });
}
