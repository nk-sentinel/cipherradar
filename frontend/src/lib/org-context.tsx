import {
  createContext,
  useContext,
  useState,
  useCallback,
  useMemo,
  useEffect,
  type ReactNode,
} from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { Org } from '@/mocks/data/admin.ts';

interface OrgContextValue {
  currentOrg: Org | null;
  setCurrentOrg: (org: Org) => void;
}

const OrgContext = createContext<OrgContextValue | null>(null);

const ORG_STORAGE_KEY = 'cipherradar-org';

export function OrgProvider({
  children,
  orgs,
}: {
  children: ReactNode;
  orgs: Org[];
}): React.ReactElement {
  const queryClient = useQueryClient();

  const [currentOrg, setCurrentOrgState] = useState<Org | null>(() => {
    try {
      const stored = sessionStorage.getItem(ORG_STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored) as Org;
        const match = orgs.find((o) => o.id === parsed.id);
        if (match) return match;
      }
    } catch {
      // ignore
    }
    return orgs[0] ?? null;
  });

  useEffect(() => {
    if (!currentOrg && orgs.length > 0) {
      setCurrentOrgState(orgs[0] ?? null);
    }
  }, [orgs, currentOrg]);

  const setCurrentOrg = useCallback(
    (org: Org): void => {
      setCurrentOrgState(org);
      try {
        sessionStorage.setItem(ORG_STORAGE_KEY, JSON.stringify(org));
      } catch {
        // ignore
      }
      // Invalidate all queries to reload data for the new org
      void queryClient.invalidateQueries();
    },
    [queryClient],
  );

  const value = useMemo(
    (): OrgContextValue => ({ currentOrg, setCurrentOrg }),
    [currentOrg, setCurrentOrg],
  );

  return <OrgContext.Provider value={value}>{children}</OrgContext.Provider>;
}

export function useCurrentOrg(): OrgContextValue {
  const context = useContext(OrgContext);
  if (!context) {
    throw new Error('useCurrentOrg must be used within an OrgProvider');
  }
  return context;
}

/**
 * Like useCurrentOrg but returns null instead of throwing when
 * OrgProvider is not available. Safe to call unconditionally
 * (no Rules of Hooks violation).
 */
export function useOptionalCurrentOrg(): OrgContextValue | null {
  return useContext(OrgContext);
}
