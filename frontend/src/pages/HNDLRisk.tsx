import { useState } from 'react';
import { useParams } from '@tanstack/react-router';
import { useHNDLRisk } from '@/api/hooks/useHNDLRisk.ts';
import { cn } from '@/lib/utils.ts';
import type { DataSensitivity, UrgencyLevel } from '@/mocks/data/hndlRisk.ts';

function urgencyBadgeClass(urgency: UrgencyLevel): string {
  switch (urgency) {
    case 'urgent':
      return 'b-crit';
    case 'high':
      return 'b-high';
    case 'medium':
      return 'b-med';
    case 'low':
      return 'b-safe';
  }
}

function riskScoreColor(score: number): string {
  if (score >= 0.8) return 'var(--red)';
  if (score >= 0.6) return 'var(--orange)';
  if (score >= 0.3) return 'var(--yellow)';
  return 'var(--green)';
}

const SENSITIVITY_OPTIONS: { value: DataSensitivity; label: string }[] = [
  { value: 'public', label: 'Public' },
  { value: 'internal', label: 'Internal' },
  { value: 'confidential', label: 'Confidential' },
  { value: 'restricted', label: 'Restricted' },
];

export function HNDLRisk(): React.ReactElement {
  const { repoId } = useParams({ strict: false }) as { repoId: string };
  const [sensitivity, setSensitivity] = useState<DataSensitivity>('confidential');
  const { data, isLoading, error } = useHNDLRisk(repoId, sensitivity);

  if (isLoading) {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading HNDL risk data...</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="card">
        <p style={{ color: 'var(--red)', fontSize: '13px' }}>
          Failed to load HNDL risk assessment.
        </p>
      </div>
    );
  }

  const riskPercent = Math.round((data.riskScore ?? 0) * 100);
  const mosca = data.mosca ?? { shelfLife: 0, migrationTime: 0, quantumDeadline: 2030, currentYear: 2026, isAtRisk: false };
  const totalHorizon = (mosca.shelfLife ?? 0) + (mosca.migrationTime ?? 0);
  const yearsUntilQuantum = (mosca.quantumDeadline ?? 2030) - (mosca.currentYear ?? 2026);

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
          HNDL Risk Assessment
        </h1>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span style={{ fontSize: '12px', color: 'var(--text-3)' }}>Data Sensitivity:</span>
          <select
            className="input"
            style={{ width: '160px' }}
            value={sensitivity}
            onChange={(e) => setSensitivity(e.target.value as DataSensitivity)}
          >
            {SENSITIVITY_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Risk Score + Urgency */}
      <div className="g2" style={{ marginBottom: '16px' }}>
        <div className="card" style={{ textAlign: 'center', padding: '30px' }}>
          <div
            style={{
              fontSize: '64px',
              fontWeight: 700,
              color: riskScoreColor(data.riskScore),
            }}
          >
            {riskPercent}%
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-3)', marginTop: '4px' }}>
            HNDL Risk Score
          </div>
          <div style={{ marginTop: '12px' }}>
            <span className={cn('badge', urgencyBadgeClass(data.urgency))} style={{ fontSize: '12px' }}>
              {data.urgency.toUpperCase()}
            </span>
          </div>
        </div>

        {/* Mosca Inequality Visualization */}
        <div className="card" style={{ padding: '20px' }}>
          <div className="card-title">Mosca Inequality</div>
          <div style={{ fontSize: '11px', color: 'var(--text-3)', marginBottom: '16px' }}>
            If shelf_life + migration_time &gt; time_until_quantum, data is at risk today.
          </div>

          {/* Timeline bars */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {/* Shelf Life + Migration Time bar */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', marginBottom: '4px' }}>
                <span style={{ color: 'var(--text-2)' }}>
                  Shelf Life ({mosca.shelfLife}y) + Migration ({mosca.migrationTime}y) = {totalHorizon}y
                </span>
              </div>
              <div
                style={{
                  height: '24px',
                  background: 'var(--bg-3)',
                  borderRadius: '4px',
                  overflow: 'hidden',
                  display: 'flex',
                }}
              >
                <div
                  style={{
                    width: `${String(Math.min((mosca.shelfLife / Math.max(totalHorizon, yearsUntilQuantum)) * 100, 100))}%`,
                    background: 'var(--orange)',
                    height: '100%',
                  }}
                />
                <div
                  style={{
                    width: `${String(Math.min((mosca.migrationTime / Math.max(totalHorizon, yearsUntilQuantum)) * 100, 100))}%`,
                    background: 'var(--yellow)',
                    height: '100%',
                  }}
                />
              </div>
              <div style={{ display: 'flex', gap: '12px', marginTop: '4px', fontSize: '10px' }}>
                <span style={{ color: 'var(--orange)' }}>Shelf Life</span>
                <span style={{ color: 'var(--yellow)' }}>Migration Time</span>
              </div>
            </div>

            {/* Quantum Deadline bar */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', marginBottom: '4px' }}>
                <span style={{ color: 'var(--text-2)' }}>
                  Time Until Quantum Threat: {yearsUntilQuantum}y ({mosca.quantumDeadline})
                </span>
              </div>
              <div
                style={{
                  height: '24px',
                  background: 'var(--bg-3)',
                  borderRadius: '4px',
                  overflow: 'hidden',
                }}
              >
                <div
                  style={{
                    width: `${String(Math.min((yearsUntilQuantum / Math.max(totalHorizon, yearsUntilQuantum)) * 100, 100))}%`,
                    background: mosca.isAtRisk ? 'var(--red)' : 'var(--green)',
                    height: '100%',
                  }}
                />
              </div>
            </div>
          </div>

          {/* Verdict */}
          <div
            className={mosca.isAtRisk ? 'alert alert-error' : 'alert alert-success'}
            style={{ marginTop: '16px' }}
          >
            {mosca.isAtRisk
              ? `AT RISK: Data needs ${totalHorizon} years of protection, but quantum computers may arrive in ${yearsUntilQuantum} years. Begin PQC migration now.`
              : `Safe margin: Your protection horizon (${totalHorizon}y) is within the quantum deadline (${yearsUntilQuantum}y).`}
          </div>
        </div>
      </div>

      {/* Quantum Exposure Breakdown */}
      <div className="card" style={{ marginBottom: '16px' }}>
        <div className="card-title">Quantum Exposure Breakdown</div>
        <table>
          <thead>
            <tr>
              <th scope="col">Algorithm</th>
              <th scope="col">Usage Count</th>
              <th scope="col">Exposure Type</th>
              <th scope="col">Est. Quantum Break Year</th>
              <th scope="col">Years Remaining</th>
            </tr>
          </thead>
          <tbody>
            {(data.quantumExposures ?? []).map((exp) => {
              const yearsLeft = exp.quantumBreakYear - mosca.currentYear;
              return (
                <tr key={exp.algorithm}>
                  <td><strong>{exp.algorithm}</strong></td>
                  <td>{exp.usageCount}</td>
                  <td>
                    <span className="badge" style={{ background: 'var(--bg-3)', color: 'var(--text-2)' }}>
                      {exp.exposureType}
                    </span>
                  </td>
                  <td>{exp.quantumBreakYear}</td>
                  <td
                    style={{
                      color: yearsLeft <= 5 ? 'var(--red)' : yearsLeft <= 8 ? 'var(--orange)' : 'var(--text-1)',
                      fontWeight: yearsLeft <= 5 ? 600 : 400,
                    }}
                  >
                    {yearsLeft}y
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Recommendations */}
      <div className="card">
        <div className="card-title">Recommendations</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {(data.recommendations ?? []).map((rec, idx) => (
            <div
              key={idx}
              style={{
                display: 'flex',
                gap: '8px',
                fontSize: '12px',
                color: 'var(--text-2)',
                alignItems: 'flex-start',
              }}
            >
              <span
                style={{
                  minWidth: '20px',
                  height: '20px',
                  borderRadius: '50%',
                  background: idx === 0 ? 'var(--red)' : 'var(--accent)',
                  color: 'var(--bg-1)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '10px',
                  fontWeight: 600,
                  flexShrink: 0,
                }}
              >
                {idx + 1}
              </span>
              {rec}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
