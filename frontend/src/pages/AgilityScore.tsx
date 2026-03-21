import { useParams } from '@tanstack/react-router';
import { useAgilityScore } from '@/api/hooks/useAgilityScore.ts';

function scoreColor(score: number): string {
  if (score >= 80) return 'var(--green)';
  if (score >= 60) return 'var(--yellow)';
  if (score >= 40) return 'var(--orange)';
  return 'var(--red)';
}

function gaugeGradient(score: number): string {
  if (score >= 80) return 'var(--green)';
  if (score >= 60) return 'var(--yellow)';
  if (score >= 40) return 'var(--orange)';
  return 'var(--red)';
}

export function AgilityScore(): React.ReactElement {
  const { repoId } = useParams({ strict: false }) as { repoId: string };
  const { data, isLoading, error } = useAgilityScore(repoId);

  if (isLoading) {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading agility score...</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="card">
        <p style={{ color: 'var(--red)', fontSize: '13px' }}>
          Failed to load agility score data.
        </p>
      </div>
    );
  }

  const gaugePercent = data.overallScore;

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
          Crypto-Agility Score
        </h1>
      </div>

      {/* Overall Score Gauge */}
      <div className="card" style={{ textAlign: 'center', padding: '30px', marginBottom: '16px' }}>
        <div style={{ position: 'relative', display: 'inline-block' }}>
          {/* Gauge background */}
          <div
            style={{
              width: '160px',
              height: '160px',
              borderRadius: '50%',
              background: `conic-gradient(${gaugeGradient(gaugePercent)} ${gaugePercent * 3.6}deg, var(--bg-3) 0deg)`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            {/* Inner circle */}
            <div
              style={{
                width: '120px',
                height: '120px',
                borderRadius: '50%',
                background: 'var(--bg-1)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexDirection: 'column',
              }}
            >
              <div
                style={{
                  fontSize: '36px',
                  fontWeight: 700,
                  color: scoreColor(gaugePercent),
                }}
              >
                {gaugePercent}
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text-3)' }}>/ 100</div>
            </div>
          </div>
        </div>
        <div style={{ marginTop: '12px', fontSize: '14px', color: 'var(--text-2)' }}>
          Overall Crypto-Agility Score
        </div>
        <div style={{ fontSize: '11px', color: 'var(--text-3)', marginTop: '4px' }}>
          {gaugePercent >= 80 && 'Excellent agility — ready for rapid algorithm migration.'}
          {gaugePercent >= 60 && gaugePercent < 80 && 'Good agility — some improvements recommended.'}
          {gaugePercent >= 40 && gaugePercent < 60 && 'Moderate agility — significant refactoring needed.'}
          {gaugePercent < 40 && 'Poor agility — crypto implementations are tightly coupled.'}
        </div>
      </div>

      {/* 5 Factor Breakdown Cards */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
          gap: '12px',
          marginBottom: '16px',
        }}
      >
        {data.factors.map((factor) => (
          <div className="card" key={factor.name}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div style={{ fontSize: '13px', fontWeight: 600 }}>{factor.name}</div>
              <div
                style={{
                  fontSize: '22px',
                  fontWeight: 700,
                  color: scoreColor(factor.score),
                }}
              >
                {factor.score}
              </div>
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-3)', marginTop: '2px' }}>
              Weight: {factor.weight}%
            </div>
            <div className="progress" style={{ marginTop: '8px' }}>
              <div
                className="progress-fill"
                style={{
                  width: `${String(factor.score)}%`,
                  background: scoreColor(factor.score),
                }}
              />
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-2)', marginTop: '8px' }}>
              {factor.details}
            </div>
          </div>
        ))}
      </div>

      <div className="g2">
        {/* Recommendations */}
        <div className="card">
          <div className="card-title">Recommendations</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {data.recommendations.map((rec, idx) => (
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
                    background: 'var(--accent)',
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

        {/* Repo Comparison Table */}
        <div className="card">
          <div className="card-title">Cross-Repository Comparison</div>
          <table>
            <thead>
              <tr>
                <th>Repository</th>
                <th>Score</th>
                <th>Algo Diversity</th>
                <th>Migration Ready</th>
              </tr>
            </thead>
            <tbody>
              {data.repoComparison.map((repo) => (
                <tr key={repo.repoId}>
                  <td><strong>{repo.repoName}</strong></td>
                  <td style={{ color: scoreColor(repo.score), fontWeight: 600 }}>{repo.score}</td>
                  <td>{repo.algorithmDiversity}</td>
                  <td>{repo.migrationReadiness}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
