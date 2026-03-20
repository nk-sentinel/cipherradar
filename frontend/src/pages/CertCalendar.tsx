import { useState, useMemo, useCallback } from 'react';
import { useCertificates } from '@/api/hooks/useCertificates.ts';
import { cn } from '@/lib/utils.ts';
import type { Certificate } from '@/mocks/data/certificates.ts';

/* ---------- helpers ---------- */

function daysUntil(dateStr: string): number {
  const now = new Date();
  now.setHours(0, 0, 0, 0);
  const target = new Date(dateStr);
  target.setHours(0, 0, 0, 0);
  return Math.ceil((target.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
}

function expiryColor(days: number): string {
  if (days < 0) return 'var(--red)';
  if (days < 7) return 'var(--red)';
  if (days < 30) return 'var(--orange)';
  if (days < 90) return 'var(--yellow)';
  return 'var(--green)';
}

function expiryBadgeClass(days: number): string {
  if (days < 0) return 'b-crit';
  if (days < 7) return 'b-crit';
  if (days < 30) return 'b-high';
  if (days < 90) return 'b-med';
  return 'b-safe';
}

function expiryLabel(days: number): string {
  if (days < 0) return `Expired ${String(Math.abs(days))}d ago`;
  if (days === 0) return 'Expires today';
  return `${String(days)}d remaining`;
}

function formatDate(dateStr: string): string {
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

function getDaysInMonth(year: number, month: number): number {
  return new Date(year, month + 1, 0).getDate();
}

function getFirstDayOfMonth(year: number, month: number): number {
  return new Date(year, month, 1).getDay();
}

const MONTH_NAMES = [
  'January', 'February', 'March', 'April', 'May', 'June',
  'July', 'August', 'September', 'October', 'November', 'December',
];

/* ---------- component ---------- */

export function CertCalendar(): React.ReactElement {
  const { data: certificates, isLoading, error } = useCertificates();
  const [viewMode, setViewMode] = useState<'calendar' | 'list'>('calendar');
  const [selectedDate, setSelectedDate] = useState<string | null>(null);

  const now = new Date();
  const [currentMonth, setCurrentMonth] = useState(now.getMonth());
  const [currentYear, setCurrentYear] = useState(now.getFullYear());

  /* group certs by expiry date */
  const certsByDate = useMemo(() => {
    if (!certificates) return new Map<string, Certificate[]>();
    const map = new Map<string, Certificate[]>();
    for (const cert of certificates) {
      const date = cert.expiryDate;
      const existing = map.get(date);
      if (existing) {
        existing.push(cert);
      } else {
        map.set(date, [cert]);
      }
    }
    return map;
  }, [certificates]);

  /* certs expiring on selected date */
  const selectedCerts = useMemo(() => {
    if (!selectedDate || !certsByDate) return [];
    return certsByDate.get(selectedDate) ?? [];
  }, [selectedDate, certsByDate]);

  /* sorted certs for list view */
  const sortedCerts = useMemo(() => {
    if (!certificates) return [];
    return [...certificates].sort((a, b) => {
      return new Date(a.expiryDate).getTime() - new Date(b.expiryDate).getTime();
    });
  }, [certificates]);

  const prevMonth = useCallback(() => {
    if (currentMonth === 0) {
      setCurrentMonth(11);
      setCurrentYear((y) => y - 1);
    } else {
      setCurrentMonth((m) => m - 1);
    }
  }, [currentMonth]);

  const nextMonth = useCallback(() => {
    if (currentMonth === 11) {
      setCurrentMonth(0);
      setCurrentYear((y) => y + 1);
    } else {
      setCurrentMonth((m) => m + 1);
    }
  }, [currentMonth]);

  if (isLoading) {
    return (
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading...</p>
      </div>
    );
  }

  if (error || !certificates) {
    return (
      <div className="card">
        <p style={{ color: 'var(--red)', fontSize: '13px' }}>
          Failed to load certificate data.
        </p>
      </div>
    );
  }

  /* calendar grid */
  const daysInMonth = getDaysInMonth(currentYear, currentMonth);
  const firstDay = getFirstDayOfMonth(currentYear, currentMonth);
  const calendarDays: (number | null)[] = [];
  for (let i = 0; i < firstDay; i++) {
    calendarDays.push(null);
  }
  for (let d = 1; d <= daysInMonth; d++) {
    calendarDays.push(d);
  }

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
          Certificate Expiry Calendar
        </h1>
        <div className="topbar-right" style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <button
            className={cn('btn', viewMode === 'calendar' ? 'btn-accent' : 'btn-outline')}
            onClick={() => setViewMode('calendar')}
          >
            Calendar
          </button>
          <button
            className={cn('btn', viewMode === 'list' ? 'btn-accent' : 'btn-outline')}
            onClick={() => setViewMode('list')}
          >
            List
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="g4">
        <div className="stat">
          <div className="stat-label">Total Certs</div>
          <div className="stat-val" style={{ color: 'var(--accent)' }}>
            {certificates.length}
          </div>
        </div>
        <div className="stat">
          <div className="stat-label">Expired</div>
          <div className="stat-val" style={{ color: 'var(--red)' }}>
            {certificates.filter((c) => daysUntil(c.expiryDate) < 0).length}
          </div>
        </div>
        <div className="stat">
          <div className="stat-label">Expiring &lt; 30d</div>
          <div className="stat-val" style={{ color: 'var(--orange)' }}>
            {certificates.filter((c) => {
              const d = daysUntil(c.expiryDate);
              return d >= 0 && d < 30;
            }).length}
          </div>
        </div>
        <div className="stat">
          <div className="stat-label">Safe (&gt; 90d)</div>
          <div className="stat-val" style={{ color: 'var(--green)' }}>
            {certificates.filter((c) => daysUntil(c.expiryDate) >= 90).length}
          </div>
        </div>
      </div>

      {viewMode === 'calendar' ? (
        <div className="g21">
          {/* Calendar */}
          <div className="card">
            {/* Month header */}
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '16px',
              }}
            >
              <button className="btn btn-outline" onClick={prevMonth} style={{ padding: '4px 10px' }}>
                &larr;
              </button>
              <div style={{ fontSize: '16px', fontWeight: 700 }}>
                {MONTH_NAMES[currentMonth]} {currentYear}
              </div>
              <button className="btn btn-outline" onClick={nextMonth} style={{ padding: '4px 10px' }}>
                &rarr;
              </button>
            </div>

            {/* Day headers */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(7, 1fr)',
                gap: '2px',
                marginBottom: '4px',
              }}
            >
              {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map((d) => (
                <div
                  key={d}
                  style={{
                    textAlign: 'center',
                    fontSize: '10px',
                    fontWeight: 600,
                    color: 'var(--text-3)',
                    textTransform: 'uppercase',
                    padding: '4px',
                  }}
                >
                  {d}
                </div>
              ))}
            </div>

            {/* Calendar grid */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(7, 1fr)',
                gap: '2px',
              }}
            >
              {calendarDays.map((day, idx) => {
                if (day === null) {
                  return <div key={`empty-${String(idx)}`} style={{ minHeight: '60px' }} />;
                }

                const dateStr = `${String(currentYear)}-${String(currentMonth + 1).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
                const certsOnDay = certsByDate.get(dateStr) ?? [];
                const isSelected = selectedDate === dateStr;
                const isToday =
                  day === now.getDate() &&
                  currentMonth === now.getMonth() &&
                  currentYear === now.getFullYear();

                return (
                  <div
                    key={day}
                    onClick={() => setSelectedDate(dateStr)}
                    style={{
                      minHeight: '60px',
                      padding: '4px',
                      border: isSelected
                        ? '2px solid var(--accent)'
                        : '1px solid var(--border-light)',
                      borderRadius: 'var(--radius)',
                      cursor: 'pointer',
                      background: isToday ? 'var(--accent-dim)' : 'transparent',
                      transition: 'border-color 0.1s',
                    }}
                  >
                    <div
                      style={{
                        fontSize: '11px',
                        fontWeight: isToday ? 700 : 400,
                        color: isToday ? 'var(--accent)' : 'var(--text-2)',
                        marginBottom: '2px',
                      }}
                    >
                      {day}
                    </div>
                    {certsOnDay.map((cert) => {
                      const days = daysUntil(cert.expiryDate);
                      return (
                        <div
                          key={cert.id}
                          style={{
                            fontSize: '8px',
                            padding: '1px 3px',
                            borderRadius: '2px',
                            background: expiryColor(days),
                            color: '#000',
                            marginBottom: '1px',
                            overflow: 'hidden',
                            whiteSpace: 'nowrap',
                            textOverflow: 'ellipsis',
                            fontWeight: 600,
                          }}
                          title={cert.commonName}
                        >
                          {cert.commonName.split('.')[0]}
                        </div>
                      );
                    })}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Selected date detail */}
          <div className="card">
            <div className="card-title">
              {selectedDate ? `Certificates expiring ${formatDate(selectedDate)}` : 'Select a day'}
            </div>
            {selectedCerts.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {selectedCerts.map((cert) => (
                  <CertCard key={cert.id} cert={cert} />
                ))}
              </div>
            ) : selectedDate ? (
              <p style={{ color: 'var(--text-3)', fontSize: '12px' }}>
                No certificates expire on this date.
              </p>
            ) : (
              <p style={{ color: 'var(--text-3)', fontSize: '12px' }}>
                Click a day in the calendar to view expiring certificates.
              </p>
            )}
          </div>
        </div>
      ) : (
        /* List view */
        <div className="card">
          <div className="card-title">All Certificates (sorted by expiry date)</div>
          <table>
            <thead>
              <tr>
                <th>Common Name</th>
                <th>Issuer</th>
                <th>Algorithm</th>
                <th>Key Size</th>
                <th>Repository</th>
                <th>Expiry Date</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {sortedCerts.map((cert) => {
                const days = daysUntil(cert.expiryDate);
                return (
                  <tr key={cert.id}>
                    <td>
                      <strong>{cert.commonName}</strong>
                    </td>
                    <td>{cert.issuer}</td>
                    <td>{cert.algorithm}</td>
                    <td>{cert.keySize}</td>
                    <td>{cert.repository}</td>
                    <td style={{ color: expiryColor(days) }}>{formatDate(cert.expiryDate)}</td>
                    <td>
                      <span className={cn('badge', expiryBadgeClass(days))}>
                        {expiryLabel(days)}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/* ---------- cert card ---------- */

function CertCard({ cert }: { cert: Certificate }): React.ReactElement {
  const days = daysUntil(cert.expiryDate);
  return (
    <div
      style={{
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        padding: '10px',
        borderLeft: `3px solid ${expiryColor(days)}`,
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <strong style={{ fontSize: '13px' }}>{cert.commonName}</strong>
        <span className={cn('badge', expiryBadgeClass(days))}>{expiryLabel(days)}</span>
      </div>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(2, 1fr)',
          gap: '6px',
          marginTop: '8px',
          fontSize: '11px',
        }}
      >
        <div>
          <span style={{ color: 'var(--text-4)' }}>Issuer:</span> {cert.issuer}
        </div>
        <div>
          <span style={{ color: 'var(--text-4)' }}>Algorithm:</span> {cert.algorithm}-{cert.keySize}
        </div>
        <div>
          <span style={{ color: 'var(--text-4)' }}>Repository:</span> {cert.repository}
        </div>
        <div>
          <span style={{ color: 'var(--text-4)' }}>File:</span> {cert.file}
        </div>
      </div>
    </div>
  );
}
