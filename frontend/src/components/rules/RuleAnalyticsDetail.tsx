import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import {
  useRuleAnalytics,
  classifySignalQuality,
  formatMTTR,
  type TimeWindow,
} from '@/api/hooks/useRuleAnalytics';

interface RuleAnalyticsDetailProps {
  ruleId: string;
  timeWindow: TimeWindow;
}

const SIGNAL_COLORS: Record<string, string> = {
  Valuable: 'var(--green, #22c55e)',
  Noisy: 'var(--orange, #f59e0b)',
  Ignored: 'var(--yellow, #eab308)',
  'Pure noise': 'var(--red, #ef4444)',
};

export function RuleAnalyticsDetail({
  ruleId,
  timeWindow,
}: RuleAnalyticsDetailProps): React.ReactElement {
  const { data, isLoading } = useRuleAnalytics(ruleId, timeWindow);

  if (isLoading) {
    return (
      <div data-testid="rule-analytics-loading" style={{ padding: '12px', fontSize: '12px', color: 'var(--text-3)' }}>
        Loading analytics...
      </div>
    );
  }

  if (!data) {
    return (
      <div data-testid="rule-analytics-empty" style={{ padding: '12px', fontSize: '12px', color: 'var(--text-3)' }}>
        No analytics data available for this rule.
      </div>
    );
  }

  const signalLabel = classifySignalQuality(data.fpRate, data.fixRate);
  const signalColor = SIGNAL_COLORS[signalLabel] ?? 'var(--text-3)';

  const chartData = data.trend.map((point) => ({
    date: new Date(point.scannedAt).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
    }),
    findings: point.count,
  }));

  return (
    <div
      data-testid="rule-analytics-detail"
      style={{
        padding: '16px',
        background: 'var(--bg-2)',
        borderTop: '1px solid var(--border)',
      }}
    >
      {/* Stats row */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(5, 1fr)',
          gap: '16px',
          marginBottom: '16px',
        }}
      >
        <div>
          <div className="field-label">Total Findings</div>
          <div style={{ fontSize: '18px', fontWeight: 700 }} data-testid="analytics-total">
            {data.totalFindings}
          </div>
        </div>
        <div>
          <div className="field-label">FP Rate</div>
          <div style={{ fontSize: '18px', fontWeight: 700 }} data-testid="analytics-fp-rate">
            {data.fpRate.toFixed(1)}%
          </div>
        </div>
        <div>
          <div className="field-label">Fix Rate</div>
          <div style={{ fontSize: '18px', fontWeight: 700 }} data-testid="analytics-fix-rate">
            {data.fixRate.toFixed(1)}%
          </div>
        </div>
        <div>
          <div className="field-label">MTTR</div>
          <div style={{ fontSize: '18px', fontWeight: 700 }} data-testid="analytics-mttr">
            {formatMTTR(data.mttrSeconds)}
          </div>
        </div>
        <div>
          <div className="field-label">Signal Quality</div>
          <div
            style={{
              fontSize: '14px',
              fontWeight: 700,
              color: signalColor,
            }}
            data-testid="analytics-signal"
          >
            {signalLabel}
          </div>
        </div>
      </div>

      {/* Trend chart */}
      {chartData.length > 0 && (
        <div data-testid="analytics-trend-chart">
          <div className="field-label" style={{ marginBottom: '8px' }}>
            Findings per Scan
          </div>
          <ResponsiveContainer width="100%" height={160}>
            <LineChart data={chartData} margin={{ top: 4, right: 4, bottom: 4, left: 4 }}>
              <XAxis
                dataKey="date"
                tick={{ fontSize: 10, fill: 'var(--text-3)' }}
                axisLine={{ stroke: 'var(--border)' }}
                tickLine={false}
              />
              <YAxis
                tick={{ fontSize: 10, fill: 'var(--text-4)' }}
                axisLine={false}
                tickLine={false}
                width={36}
                allowDecimals={false}
              />
              <Tooltip
                contentStyle={{
                  background: 'var(--bg-2)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius)',
                  fontSize: '11px',
                  color: 'var(--text-1)',
                }}
              />
              <Line
                type="monotone"
                dataKey="findings"
                stroke="var(--accent)"
                strokeWidth={2}
                dot={{ r: 3, fill: 'var(--accent)' }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
