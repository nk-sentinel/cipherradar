import { useQuery } from '@tanstack/react-query';
import type { Certificate } from '@/mocks/data/certificates.ts';

/**
 * Fetch all certificates for the calendar view.
 * No backend endpoint yet — always uses mock data.
 */
export function useCertificates() {
  return useQuery({
    queryKey: ['certificates'],
    queryFn: async () => {
      const { getCertificates } = await import('@/mocks/data/certificates.ts');
      return getCertificates() as Certificate[];
    },
    staleTime: 60_000,
  });
}
