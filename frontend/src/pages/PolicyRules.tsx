import { useState } from 'react';

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

function severityBadge(severity: string): string {
  if (severity === 'critical') return 'b-crit';
  if (severity === 'high') return 'b-high';
  return 'b-med';
}

export function PolicyRules(): React.ReactElement {
  const [rules, setRules] = useState<PolicyRule[]>(POLICY_RULES);

  const toggleRule = (id: string) => {
    setRules((prev) =>
      prev.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r)),
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
        <div style={{ fontSize: '12px', color: 'var(--text-3)' }}>
          {enabledCount} of {rules.length} rules enabled
        </div>
      </div>

      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Rule</th>
              <th>Category</th>
              <th>Severity</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule) => (
              <tr key={rule.id}>
                <td>
                  <div style={{ fontWeight: 600, fontSize: '12px' }}>{rule.name}</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-3)', marginTop: '2px' }}>
                    {rule.description}
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
                <td>
                  <button
                    className={`btn ${rule.enabled ? 'btn-accent' : 'btn-outline'}`}
                    onClick={() => toggleRule(rule.id)}
                    style={{ fontSize: '11px', padding: '4px 10px' }}
                  >
                    {rule.enabled ? 'Enabled' : 'Disabled'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
