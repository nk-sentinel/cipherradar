import { useState, useEffect } from 'react';
import { useSchedule, useSaveSchedule, type SaveScheduleParams } from '@/api/hooks/useSchedule';

const PRESETS = [
  { value: 'off', label: 'Off' },
  { value: 'daily', label: 'Daily' },
  { value: 'weekly', label: 'Weekly' },
] as const;

const HOURS = Array.from({ length: 24 }, (_, i) => i);

const TIMEZONES = [
  'UTC',
  'America/New_York',
  'America/Chicago',
  'America/Denver',
  'America/Los_Angeles',
  'Europe/London',
  'Europe/Berlin',
  'Europe/Paris',
  'Asia/Tokyo',
  'Asia/Shanghai',
  'Asia/Kolkata',
  'Australia/Sydney',
];

const SOURCE_LABELS: Record<string, string> = {
  project: 'Project',
  group: 'Inherited from group',
  org: 'Inherited from organization',
  none: 'No schedule configured',
};

interface ScheduleConfigProps {
  scopeType: 'projects' | 'groups' | 'orgs';
  scopeId: string;
}

export function ScheduleConfig({ scopeType, scopeId }: ScheduleConfigProps): React.ReactElement {
  const { data: schedule, isLoading } = useSchedule(scopeType, scopeId);
  const saveMutation = useSaveSchedule(scopeType, scopeId);

  const [preset, setPreset] = useState<'off' | 'daily' | 'weekly'>('off');
  const [hour, setHour] = useState(2);
  const [timezone, setTimezone] = useState('UTC');

  useEffect(() => {
    if (schedule) {
      setPreset(schedule.preset);
      setHour(schedule.hour);
      setTimezone(schedule.timezone);
    }
  }, [schedule]);

  function handleSave() {
    const params: SaveScheduleParams = { preset, hour, timezone };
    saveMutation.mutate(params);
  }

  const isInherited = schedule?.source === 'group' || schedule?.source === 'org';

  if (isLoading) {
    return (
      <div className="card" data-testid="schedule-config">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading schedule...</p>
      </div>
    );
  }

  return (
    <div className="card" data-testid="schedule-config" style={{ padding: '20px' }}>
      <h3 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-1)', marginBottom: '16px' }}>
        Scan Schedule
      </h3>

      {/* Inheritance source indicator */}
      {schedule && schedule.source !== 'none' && (
        <div
          data-testid="schedule-source"
          style={{
            fontSize: '11px',
            color: isInherited ? 'var(--amber)' : 'var(--text-3)',
            marginBottom: '12px',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}
        >
          {isInherited && (
            <span style={{ color: 'var(--amber)' }}>&#9888;</span>
          )}
          {SOURCE_LABELS[schedule.source] ?? schedule.source}
          {isInherited && (
            <span style={{ fontStyle: 'italic' }}>(override below to customize)</span>
          )}
        </div>
      )}

      {/* Preset selector */}
      <div style={{ marginBottom: '12px' }}>
        <label style={{ fontSize: '11px', color: 'var(--text-3)', display: 'block', marginBottom: '4px' }}>
          Frequency
        </label>
        <div data-testid="schedule-presets" style={{ display: 'flex', gap: '6px' }}>
          {PRESETS.map((p) => (
            <button
              key={p.value}
              data-testid={`preset-${p.value}`}
              className={`btn ${preset === p.value ? 'btn-accent' : 'btn-outline'}`}
              onClick={() => setPreset(p.value)}
              type="button"
              style={{ flex: 1, fontSize: '12px', padding: '6px 10px' }}
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* Time picker (only if not off) */}
      {preset !== 'off' && (
        <>
          <div style={{ marginBottom: '12px' }}>
            <label style={{ fontSize: '11px', color: 'var(--text-3)', display: 'block', marginBottom: '4px' }}>
              Hour (24h)
            </label>
            <select
              data-testid="schedule-hour"
              value={hour}
              onChange={(e) => setHour(Number(e.target.value))}
              style={{
                width: '100%',
                padding: '6px 10px',
                fontSize: '13px',
                background: 'var(--bg-2)',
                color: 'var(--text-1)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
              }}
            >
              {HOURS.map((h) => (
                <option key={h} value={h}>
                  {String(h).padStart(2, '0')}:00
                </option>
              ))}
            </select>
          </div>

          <div style={{ marginBottom: '16px' }}>
            <label style={{ fontSize: '11px', color: 'var(--text-3)', display: 'block', marginBottom: '4px' }}>
              Timezone
            </label>
            <select
              data-testid="schedule-timezone"
              value={timezone}
              onChange={(e) => setTimezone(e.target.value)}
              style={{
                width: '100%',
                padding: '6px 10px',
                fontSize: '13px',
                background: 'var(--bg-2)',
                color: 'var(--text-1)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius)',
              }}
            >
              {TIMEZONES.map((tz) => (
                <option key={tz} value={tz}>{tz}</option>
              ))}
            </select>
          </div>
        </>
      )}

      {/* Next run display */}
      {schedule?.nextRun && preset !== 'off' && (
        <div
          data-testid="schedule-next-run"
          style={{
            fontSize: '11px',
            color: 'var(--text-3)',
            marginBottom: '16px',
            padding: '8px 12px',
            background: 'var(--bg-2)',
            borderRadius: 'var(--radius)',
          }}
        >
          Next run: {new Date(schedule.nextRun).toLocaleString()}
        </div>
      )}

      <button
        data-testid="schedule-save"
        className="btn btn-accent"
        onClick={handleSave}
        disabled={saveMutation.isPending}
        type="button"
        style={{ width: '100%' }}
      >
        {saveMutation.isPending ? 'Saving...' : 'Save Schedule'}
      </button>
    </div>
  );
}
