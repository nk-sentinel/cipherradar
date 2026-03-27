import { useState } from 'react';
import { useParams } from '@tanstack/react-router';
import { RepoCompliance } from './RepoCompliance';
import { RepoQuantum } from './RepoQuantum';

type ComplianceSection = 'frameworks' | 'quantum';

export function RepoComplianceUnified(): React.ReactElement {
  const { repoId } = useParams({ strict: false }) as { repoId: string };
  const [section, setSection] = useState<ComplianceSection>('frameworks');

  void repoId; // used by child components via params

  return (
    <div>
      <div
        style={{
          display: 'flex',
          gap: '8px',
          marginBottom: '16px',
          borderBottom: '1px solid var(--border)',
          paddingBottom: '8px',
        }}
      >
        <button
          className={`btn ${section === 'frameworks' ? 'btn-primary' : 'btn-outline'}`}
          onClick={() => setSection('frameworks')}
          data-testid="compliance-section-frameworks"
        >
          Frameworks
        </button>
        <button
          className={`btn ${section === 'quantum' ? 'btn-primary' : 'btn-outline'}`}
          onClick={() => setSection('quantum')}
          data-testid="compliance-section-quantum"
        >
          Quantum Readiness
        </button>
      </div>

      {section === 'frameworks' && <RepoCompliance />}
      {section === 'quantum' && <RepoQuantum />}
    </div>
  );
}
