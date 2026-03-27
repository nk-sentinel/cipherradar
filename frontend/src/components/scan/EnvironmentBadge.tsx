interface EnvironmentBadgeProps {
  environment: string;
}

const ENV_STYLES: Record<string, { bg: string; color: string; border: string }> = {
  dev: { bg: 'var(--bg-3)', color: 'var(--text-2)', border: 'var(--border)' },
  staging: { bg: 'rgba(245, 158, 11, 0.1)', color: 'var(--amber)', border: 'var(--amber)' },
  production: { bg: 'rgba(34, 197, 94, 0.1)', color: 'var(--green)', border: 'var(--green)' },
};

export function EnvironmentBadge({ environment }: EnvironmentBadgeProps): React.ReactElement {
  const style = ENV_STYLES[environment] ?? ENV_STYLES['dev']!;

  return (
    <span
      data-testid={`env-badge-${environment}`}
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        fontSize: '10px',
        fontWeight: 600,
        textTransform: 'uppercase',
        letterSpacing: '0.05em',
        borderRadius: 'var(--radius)',
        background: style.bg,
        color: style.color,
        border: `1px solid ${style.border}`,
      }}
    >
      {environment}
    </span>
  );
}
