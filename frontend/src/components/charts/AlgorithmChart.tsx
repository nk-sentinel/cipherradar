import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';

interface AlgorithmData {
  name: string;
  count: number;
}

interface AlgorithmChartProps {
  data: AlgorithmData[];
}

export function AlgorithmChart({ data }: AlgorithmChartProps): React.ReactElement {
  return (
    <div className="card">
      <div className="card-title">Top Algorithms</div>
      <ResponsiveContainer width="100%" height={180}>
        <BarChart data={data} margin={{ top: 4, right: 4, bottom: 4, left: 4 }}>
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
          <Bar
            dataKey="count"
            fill="var(--accent)"
            radius={[2, 2, 0, 0]}
            maxBarSize={40}
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
