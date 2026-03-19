import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';

interface SeverityData {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

interface SeverityChartProps {
  data: SeverityData;
}

interface ChartEntry {
  name: string;
  value: number;
  color: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  Critical: 'var(--red)',
  High: 'var(--orange)',
  Medium: 'var(--yellow)',
  Low: 'var(--blue)',
  Info: 'var(--text-3)',
};

export function SeverityChart({ data }: SeverityChartProps): React.ReactElement {
  const chartData: ChartEntry[] = [
    { name: 'Critical', value: data.critical, color: SEVERITY_COLORS['Critical'] as string },
    { name: 'High', value: data.high, color: SEVERITY_COLORS['High'] as string },
    { name: 'Medium', value: data.medium, color: SEVERITY_COLORS['Medium'] as string },
    { name: 'Low', value: data.low, color: SEVERITY_COLORS['Low'] as string },
    { name: 'Info', value: data.info, color: SEVERITY_COLORS['Info'] as string },
  ];

  return (
    <div className="card">
      <div className="card-title">Severity Distribution</div>
      <ResponsiveContainer width="100%" height={180}>
        <BarChart data={chartData} margin={{ top: 4, right: 4, bottom: 4, left: 4 }}>
          <XAxis
            dataKey="name"
            tick={{ fontSize: 10, fill: 'var(--text-3)' }}
            axisLine={{ stroke: 'var(--border)' }}
            tickLine={false}
          />
          <YAxis
            tick={{ fontSize: 10, fill: 'var(--text-4)' }}
            axisLine={false}
            tickLine={false}
            width={36}
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
          <Bar dataKey="value" radius={[2, 2, 0, 0]} maxBarSize={40}>
            {chartData.map((entry) => (
              <Cell key={entry.name} fill={entry.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
