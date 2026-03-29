import { useState, useEffect } from 'react';
import {
  useRulesSummary,
  formatMTTR,
  type TimeWindow,
  type RuleSummary,
} from '@/api/hooks/useRuleAnalytics';
import { RuleAnalyticsDetail } from '@/components/rules/RuleAnalyticsDetail';
import { CustomRulesPanel } from '@/components/rules/CustomRulesPanel';
import {
  usePolicy,
  useSavePolicy,
  type PolicyRuleConfig,
  type PolicyScope,
  type PolicySeverity,
} from '@/api/hooks/usePolicy';
import { useToast } from '@/lib/use-toast';
import { useAuth } from '@/lib/auth';

// ---------------------------------------------------------------------------
// Exported constants (tested)
// ---------------------------------------------------------------------------

export const SEVERITY_OPTIONS: { value: PolicySeverity; label: string }[] = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
];

export const SCOPE_OPTIONS: { value: PolicyScope; label: string }[] = [
  { value: 'org', label: 'Organization' },
  { value: 'group', label: 'Group' },
  { value: 'project', label: 'Project' },
];

// ---------------------------------------------------------------------------
// Local types
// ---------------------------------------------------------------------------

interface PolicyRule {
  id: string;
  name: string;
  description: string;
  severity: PolicySeverity;
  enabled: boolean;
  category: string;
  // Policy cascade fields (D26)
  locked: boolean;
  scope: PolicyScope;
  inheritedFrom: string | null;
  overridden: boolean;
}

const BASE_RULES: Omit<PolicyRule, 'locked' | 'scope' | 'inheritedFrom' | 'overridden'>[] = [
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------


function getMetrics(ruleId: string, summaryData: RuleSummary[] | undefined): RuleSummary | null {
  if (!summaryData) return null;
  return summaryData.find((s) => s.ruleId === ruleId) ?? null;
}

function mergeRulesWithPolicy(
  policyRules: PolicyRuleConfig[] | undefined,
): PolicyRule[] {
  return BASE_RULES.map((base) => {
    const policyConfig = policyRules?.find((p) => p.id === base.id);
    const defaultSeverity = base.severity;
    const overridden = policyConfig
      ? policyConfig.severity !== defaultSeverity
      : false;
    return {
      ...base,
      severity: policyConfig?.severity ?? base.severity,
      enabled: policyConfig?.enabled ?? base.enabled,
      locked: policyConfig?.locked ?? false,
      scope: policyConfig?.scope ?? 'org',
      inheritedFrom: policyConfig?.inheritedFrom ?? null,
      overridden,
    };
  });
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export function PolicyRules(): React.ReactElement {
  const { data: policyData } = usePolicy();
  const savePolicy = useSavePolicy();
  const { toast } = useToast();
  const auth = useAuth();
  const isOrgAdmin = auth.user?.role === 'org-admin';
  const canEdit = auth.user?.role === 'org-admin' || auth.user?.role === 'security-manager';
  const canLock = auth.user?.role === 'org-admin';

  const [rules, setRules] = useState<PolicyRule[]>(() => mergeRulesWithPolicy(undefined));
  const [timeWindow, setTimeWindow] = useState<TimeWindow>('90d');
  const [expandedRule, setExpandedRule] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);

  const { data: summaryData } = useRulesSummary(timeWindow);

  // Hydrate from API
  useEffect(() => {
    if (policyData?.rules) {
      setRules(mergeRulesWithPolicy(policyData.rules));
    }
  }, [policyData]);

  const toggleRule = (id: string) => {
    setRules((prev) =>
      prev.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r)),
    );
    setDirty(true);
  };

  const toggleExpand = (id: string) => {
    setExpandedRule((prev) => (prev === id ? null : id));
  };

  const changeSeverity = (id: string, severity: PolicySeverity) => {
    setRules((prev) =>
      prev.map((r) => {
        if (r.id !== id) return r;
        const base = BASE_RULES.find((b) => b.id === id);
        return {
          ...r,
          severity,
          overridden: base ? severity !== base.severity : false,
        };
      }),
    );
    setDirty(true);
  };

  const changeScope = (id: string, scope: PolicyScope) => {
    setRules((prev) =>
      prev.map((r) => (r.id === id ? { ...r, scope } : r)),
    );
    setDirty(true);
  };

  const toggleLock = (id: string) => {
    if (!isOrgAdmin) return;
    setRules((prev) =>
      prev.map((r) => (r.id === id ? { ...r, locked: !r.locked } : r)),
    );
    setDirty(true);
  };

  const handleSave = () => {
    const payload = rules.map((r) => ({
      id: r.id,
      severity: r.severity,
      enabled: r.enabled,
      locked: r.locked,
      scope: r.scope,
      inheritedFrom: r.inheritedFrom,
    }));
    savePolicy.mutate(
      { rules: payload },
      {
        onSuccess: () => {
          toast({ title: 'Policy saved', variant: 'success' });
          setDirty(false);
        },
        onError: () => {
          toast({ title: 'Failed to save policy', variant: 'error' });
        },
      },
    );
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
          {dirty && (
            <button
              className="btn btn-accent"
              style={{ fontSize: '11px', padding: '4px 12px' }}
              disabled={savePolicy.isPending}
              onClick={handleSave}
              data-testid="save-policy-btn"
            >
              {savePolicy.isPending ? 'Saving...' : 'Save Policy'}
            </button>
          )}
        </div>
      </div>

      <div className="card">
        <table>
          <thead>
            <tr>
              <th scope="col">Rule</th>
              <th scope="col">Category</th>
              <th scope="col">Severity</th>
              <th scope="col">Scope</th>
              <th scope="col" data-testid="col-findings">Findings</th>
              <th scope="col" data-testid="col-fp-rate">FP Rate</th>
              <th scope="col" data-testid="col-fix-rate">Fix Rate</th>
              <th scope="col" data-testid="col-mttr">MTTR</th>
              <th scope="col">Status</th>
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
                  isOrgAdmin={isOrgAdmin}
                  canEdit={canEdit}
                  canLock={canLock}
                  onToggleRule={toggleRule}
                  onToggleExpand={toggleExpand}
                  onChangeSeverity={changeSeverity}
                  onChangeScope={changeScope}
                  onToggleLock={toggleLock}
                />
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Custom Rules Panel (D27) */}
      <div className="card" style={{ marginTop: '16px' }}>
        <CustomRulesPanel />
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
  isOrgAdmin: boolean;
  canEdit: boolean;
  canLock: boolean;
  onToggleRule: (id: string) => void;
  onToggleExpand: (id: string) => void;
  onChangeSeverity: (id: string, severity: PolicySeverity) => void;
  onChangeScope: (id: string, scope: PolicyScope) => void;
  onToggleLock: (id: string) => void;
}

function RuleRow({
  rule,
  metrics,
  isExpanded,
  showWarning,
  timeWindow,
  isOrgAdmin,
  canEdit,
  canLock,
  onToggleRule,
  onToggleExpand,
  onChangeSeverity,
  onChangeScope,
  onToggleLock,
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
            {/* Lock icon (D26) — OA only */}
            {canLock && (
              <button
                data-testid={`lock-${rule.id}`}
                title={rule.locked ? 'Click to unlock' : 'Click to lock'}
                style={{
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  fontSize: '12px',
                  padding: '0 2px',
                  color: rule.locked ? 'var(--orange)' : 'var(--text-4)',
                }}
                onClick={(e) => {
                  e.stopPropagation();
                  onToggleLock(rule.id);
                }}
              >
                {rule.locked ? '\uD83D\uDD12' : '\uD83D\uDD13'}
              </button>
            )}
            {!canLock && rule.locked && (
              <span
                data-testid={`lock-${rule.id}`}
                title="Locked by Org Admin"
                style={{
                  fontSize: '12px',
                  padding: '0 2px',
                  color: 'var(--orange)',
                  opacity: 0.5,
                }}
              >
                {'\uD83D\uDD12'}
              </span>
            )}

            <span style={{ fontSize: '10px', color: 'var(--text-3)' }}>
              {isExpanded ? '\u25BC' : '\u25B6'}
            </span>
            <div>
              <div style={{ fontWeight: 600, fontSize: '12px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                {rule.name}
                {/* Override badge (D26) */}
                {rule.overridden && (
                  <span
                    data-testid={`override-badge-${rule.id}`}
                    style={{
                      fontSize: '9px',
                      padding: '1px 4px',
                      borderRadius: 'var(--radius)',
                      background: 'var(--purple)',
                      color: '#fff',
                      fontWeight: 600,
                    }}
                  >
                    Override
                  </span>
                )}
                {showWarning && (
                  <span
                    data-testid={`warning-${rule.id}`}
                    title="High FP rate or low fix rate"
                    style={{
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
              {/* Inherited-from indicator (D26) */}
              {rule.inheritedFrom && (
                <div
                  data-testid={`inherited-from-${rule.id}`}
                  style={{ fontSize: '10px', color: 'var(--text-4)', marginTop: '2px' }}
                >
                  Inherited from: {rule.inheritedFrom}
                </div>
              )}
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
        {/* Severity override dropdown (D26) */}
        <td>
          <select
            className="input"
            style={{ fontSize: '10px', padding: '2px 4px', width: 'auto' }}
            value={rule.severity}
            onClick={(e) => e.stopPropagation()}
            onChange={(e) => {
              e.stopPropagation();
              onChangeSeverity(rule.id, e.target.value as PolicySeverity);
            }}
            disabled={!canEdit || (rule.locked && !isOrgAdmin)}
            data-testid={`severity-select-${rule.id}`}
            aria-label={`Severity for ${rule.name}`}
          >
            {SEVERITY_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </td>
        {/* Scope selector (D26) */}
        <td>
          <select
            className="input"
            style={{ fontSize: '10px', padding: '2px 4px', width: 'auto' }}
            value={rule.scope}
            onClick={(e) => e.stopPropagation()}
            onChange={(e) => {
              e.stopPropagation();
              onChangeScope(rule.id, e.target.value as PolicyScope);
            }}
            disabled={!canEdit || (rule.locked && !isOrgAdmin)}
            data-testid={`scope-select-${rule.id}`}
            aria-label={`Scope for ${rule.name}`}
          >
            {SCOPE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
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
            disabled={!canEdit || (rule.locked && !isOrgAdmin)}
            style={{ fontSize: '11px', padding: '4px 10px' }}
          >
            {rule.enabled ? 'Enabled' : 'Disabled'}
          </button>
        </td>
      </tr>
      {isExpanded && (
        <tr data-testid={`rule-expanded-${rule.id}`}>
          <td colSpan={9} style={{ padding: 0 }}>
            <RuleAnalyticsDetail ruleId={rule.id} timeWindow={timeWindow} />
          </td>
        </tr>
      )}
    </>
  );
}
