import { cn } from '@/lib/utils';

export type SourceType = 'repository' | 'container' | 'artifact';

interface ScanSourceTabsProps {
  active: SourceType;
  onChange: (tab: SourceType) => void;
}

const TABS: { key: SourceType; label: string }[] = [
  { key: 'repository', label: 'Repository' },
  { key: 'container', label: 'Container' },
  { key: 'artifact', label: 'Artifact' },
];

export function ScanSourceTabs({ active, onChange }: ScanSourceTabsProps): React.ReactElement {
  return (
    <div className="scan-source-tabs" style={{ display: 'flex', gap: '4px', marginBottom: '16px' }}>
      {TABS.map((tab) => (
        <button
          key={tab.key}
          data-testid={`tab-${tab.key}`}
          className={cn('btn', active === tab.key ? 'btn-accent' : 'btn-outline')}
          style={{ flex: 1, fontSize: '12px', padding: '6px 12px' }}
          onClick={() => onChange(tab.key)}
          type="button"
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}
