import { useState } from 'react';
import {
  useRulesSummary,
  formatMTTR,
  type TimeWindow,
  type RuleSummary,
} from '@/api/hooks/useRuleAnalytics';
import { RuleAnalyticsDetail } from '@/components/rules/RuleAnalyticsDetail';

interface PolicyRule {
  id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium';
  enabled: boolean;
  category: string;
}

const POLICY_RULES: PolicyRule[] = [
  {
    id: 'no-broken-algorithms',
    name: 'No Broken Algorithms',
    description:
      'Flag any usage of DES, 3DES, RC4, MD4, or MD5 — algorithms that are known to be cryptographically broken.',
    severity: 'critical',
    enabled: true,
    category: 'Algorithm Strength',
  },
  {
    id: 'no-ecb-mode',
    name: 'No ECB Mode',
    description:
      'Prohibit ECB block cipher mode. ECB leaks plaintext patterns and must not be used for encrypting more than one block.',
    severity: 'high',
    enabled: true,
    category: 'Algorithm Strength',
  },
  {
    id: 'rsa-min-key-size',
    name: 'RSA Minimum Key Size',
    description:
      'RSA keys must be at least 2048 bits. Keys below this threshold are vulnerable to factoring attacks.',
    severity: 'high',
    enabled: true,
    category: 'Key Management',
  },
  {
    id: 'no-deprecated-tls',
    name: 'No Deprecated TLS',
    description:
      'Disallow TLS 1.0 and TLS 1.1. Only TLS 1.2+ (preferably 1.3) should be used for transport security.',
    severity: 'high',
    enabled: true,
    category: 'Protocol',
  },
  {
    id: 'quantum-vulnerable',
    name: 'Quantum-Vulnerable Detection',
    description:
      'Identify RSA, ECDSA, ECDH, and DH usage that will be broken by cryptographically relevant quantum computers. Flag for PQC migration planning.',
    severity: 'medium',
    enabled: true,
    category: 'Quantum Readiness',
  },
  {
    id: 'no-hardcoded-keys',
    name: 'No Hardcoded Keys',
    description:
      'Detect private keys, API secrets, or symmetric keys embedded directly in source code. Keys must be loaded from secure key stores.',
    severity: 'critical',
    enabled: true,
    category: 'Key Management',
  },
];

const TIME_WINDOWS: { value: TimeWindow; label: string }[] = [
  { value: '30d', label: '30 days' },
  { value: '90d', label: '90 days' },
  { value: '180d', label: '180 days' },
  { value: '1y', label: '1 year' },
  { value: 'all', label: 'All time' },
];

function severityBadge(severity: string): string {
  if (severity === 'critical') return 'b-crit';
  if (severity === 'high') return 'b-high';
  return 'b-med';
}

function getMetrics(ruleId: string, summaryData: RuleSummary[] | undefined): RuleSummary | null {
  if (!summaryData) return null;
  return summaryData.find((s) => s.ruleId === ruleId) ?? null;
}

export function PolicyRules(): React.ReactElement {
  const [rules, setRules] = useState<PolicyRule[]>(POLICY_RULES);
  const [timeWindow, setTimeWindow] = useState<TimeWindow>('90d');
  const [expandedRule, setExpandedRule] = useState<string | null>(null);

  const { data: summaryData } = useRulesSummary(timeWindow);

  const toggleRule = (id: string) => {
    setRules((prev) =>
      prev.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r)),
    );
  };

  const toggleExpand = (id: string) => {
    setExpandedRule((prev) => (prev === id ? null : id));
  };

  const enabledCount = rules.filter((r) => r.enabled).length;

  return (
    <div>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '20px',
        }}
      >
        <h1
          style={{
            fontSize: '18px',
            fontWeight: 700,
            textTransform: 'var(--tt)' as React.CSSProperties['textTransform'],
            letterSpacing: '0.04em',
          }}
        >
          Policy Rules
        </h1>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-3)' }}>
            {enabledCount} of {rules.length} rules enabled
          </div>
          <select
            className="input"
            style={{ fontSize: '11px', padding: '4px 8px', width: 'auto' }}
            value={timeWindow}
            onChange={(e) => setTimeWindow(e.target.value as TimeWindow)}
            data-testid="time-window-selector"
            aria-label="Time window"
          >
            {TIME_WINDOWS.map((tw) => (
              <option key={tw.value} value={tw.value}>
                {tw.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Rule</th>
              <th>Category</th>
              <th>Severity</th>
              <th data-testid="col-findings">Findings</th>
              <th data-testid="col-fp-rate">FP Rate</th>
              <th data-testid="col-fix-rate">Fix Rate</th>
              <th data-testid="col-mttr">MTTR</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule) => {
              const metrics = getMetrics(rule.id, summaryData);
              const isExpanded = expandedRule === rule.id;
              const showWarning = metrics?.warning ?? false;

              return (
                <RuleRow
                  key={rule.id}
                  rule={rule}
                  metrics={metrics}
                  isExpanded={isExpanded}
                  showWarning={showWarning}
                  timeWindow={timeWindow}
                  onToggleRule={toggleRule}
                  onToggleExpand={toggleExpand}
                />
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// RuleRow — extracted for clarity
// ---------------------------------------------------------------------------

interface RuleRowProps {
  rule: PolicyRule;
  metrics: RuleSummary | null;
  isExpanded: boolean;
  showWarning: boolean;
  timeWindow: TimeWindow;
  onToggleRule: (id: string) => void;
  onToggleExpand: (id: string) => void;
}

function RuleRow({
  rule,
  metrics,
  isExpanded,
  showWarning,
  timeWindow,
  onToggleRule,
  onToggleExpand,
}: RuleRowProps): React.ReactElement {
  return (
    <>
      <tr
        data-testid={`rule-row-${rule.id}`}
        style={{ cursor: 'pointer' }}
        onClick={() => onToggleExpand(rule.id)}
      >
        <td>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ fontSize: '10px', color: 'var(--text-3)' }}>
              {isExpanded ? '\u25BC' : '\u25B6'}
            </span>
            <div>
              <div style={{ fontWeight: 600, fontSize: '12px' }}>
                {rule.name}
                {showWarning && (
                  <span
                    data-testid={`warning-${rule.id}`}
                    title="High FP rate or low fix rate"
                    style={{
                      marginLeft: '6px',
                      color: 'var(--orange, #f59e0b)',
                      fontSize: '14px',
                    }}
                  >
                    {'\u26A0'}
                  </span>
                )}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-3)', marginTop: '2px' }}>
                {rule.description}
              </div>
            </div>
          </div>
        </td>
        <td>
          <span
            style={{
              fontSize: '10px',
              padding: '2px 6px',
              borderRadius: 'var(--radius)',
              border: '1px solid var(--border)',
              color: 'var(--text-3)',
            }}
          >
            {rule.category}
          </span>
        </td>
        <td>
          <span className={`badge ${severityBadge(rule.severity)}`}>
            {rule.severity}
          </span>
        </td>
        <td style={{ fontSize: '12px', textAlign: 'center' }} data-testid={`findings-count-${rule.id}`}>
          {metrics ? metrics.totalFindings : '\u2014'}
        </td>
        <td style={{ fontSize: '12px', textAlign: 'center' }} data-testid={`fp-rate-${rule.id}`}>
          {metrics ? `${metrics.fpRate.toFixed(1)}%` : '\u2014'}
        </td>
        <td style={{ fontSize: '12px', textAlign: 'center' }} data-testid={`fix-rate-${rule.id}`}>
          {metrics ? `${metrics.fixRate.toFixed(1)}%` : '\u2014'}
        </td>
        <td style={{ fontSize: '12px', textAlign: 'center' }} data-testid={`mttr-${rule.id}`}>
          {metrics ? formatMTTR(metrics.mttrSeconds) : '\u2014'}
        </td>
        <td>
          <button
            className={`btn ${rule.enabled ? 'btn-accent' : 'btn-outline'}`}
            onClick={(e) => {
              e.stopPropagation();
              onToggleRule(rule.id);
            }}
            style={{ fontSize: '11px', padding: '4px 10px' }}
          >
            {rule.enabled ? 'Enabled' : 'Disabled'}
          </button>
        </td>
      </tr>
      {isExpanded && (
        <tr data-testid={`rule-expanded-${rule.id}`}>
          <td colSpan={8} style={{ padding: 0 }}>
            <RuleAnalyticsDetail ruleId={rule.id} timeWindow={timeWindow} />
          </td>
        </tr>
      )}
    </>
  );
}
