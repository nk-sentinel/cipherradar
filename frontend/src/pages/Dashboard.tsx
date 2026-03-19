export function Dashboard(): React.ReactElement {
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
          Dashboard
        </h1>
      </div>
      <div className="card">
        <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>
          Dashboard content will be implemented in C-M2.
        </p>
      </div>
    </div>
  );
}
