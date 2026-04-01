import { useState } from 'react';
import { cn } from '@/lib/utils.ts';

type Flavor = 'light' | 'full';

interface DownloadCard {
  os: string;
  osIcon: string;
  name: string;
  arch: string;
  fileLight: string;
  sizeLight: string;
  fileFull: string;
  sizeFull: string;
}

const DOWNLOADS: DownloadCard[] = [
  {
    os: 'macOS',
    osIcon: '\u{F8FF}',
    name: 'macOS (Apple Silicon)',
    arch: 'darwin / arm64',
    fileLight: 'cbom_0.1.0_darwin_arm64.tar.gz',
    sizeLight: '14.2 MB',
    fileFull: 'cbom-full_0.1.0_darwin_arm64.tar.gz',
    sizeFull: '78.3 MB',
  },
  {
    os: 'macOS',
    osIcon: '\u{F8FF}',
    name: 'macOS (Intel)',
    arch: 'darwin / amd64',
    fileLight: 'cbom_0.1.0_darwin_amd64.tar.gz',
    sizeLight: '15.1 MB',
    fileFull: 'cbom-full_0.1.0_darwin_amd64.tar.gz',
    sizeFull: '82.1 MB',
  },
  {
    os: 'Linux',
    osIcon: '\u{1F427}',
    name: 'Linux (x86_64)',
    arch: 'linux / amd64',
    fileLight: 'cbom_0.1.0_linux_amd64.tar.gz',
    sizeLight: '14.8 MB',
    fileFull: 'cbom-full_0.1.0_linux_amd64.tar.gz',
    sizeFull: '80.5 MB',
  },
  {
    os: 'Linux',
    osIcon: '\u{1F427}',
    name: 'Linux (ARM64)',
    arch: 'linux / arm64',
    fileLight: 'cbom_0.1.0_linux_arm64.tar.gz',
    sizeLight: '13.9 MB',
    fileFull: 'cbom-full_0.1.0_linux_arm64.tar.gz',
    sizeFull: '76.8 MB',
  },
  {
    os: 'Windows',
    osIcon: '\u{1F3F3}\u{FE0F}',
    name: 'Windows (x86_64)',
    arch: 'windows / amd64',
    fileLight: 'cbom_0.1.0_windows_amd64.zip',
    sizeLight: '15.4 MB',
    fileFull: 'cbom-full_0.1.0_windows_amd64.zip',
    sizeFull: '83.2 MB',
  },
];

const CHECKSUMS = [
  { hash: 'a1b2c3d4...', file: 'cbom_0.1.0_darwin_arm64.tar.gz' },
  { hash: 'e5f6g7h8...', file: 'cbom_0.1.0_darwin_amd64.tar.gz' },
  { hash: 'i9j0k1l2...', file: 'cbom_0.1.0_linux_amd64.tar.gz' },
  { hash: 'm3n4o5p6...', file: 'cbom_0.1.0_linux_arm64.tar.gz' },
  { hash: 'q7r8s9t0...', file: 'cbom_0.1.0_windows_amd64.zip' },
];

export function Downloads(): React.ReactElement {
  const [flavor, setFlavor] = useState<Flavor>('light');

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
          CLI Downloads
        </h1>
        <div className="topbar-right">
          <span style={{ color: 'var(--green)' }}>Latest: v0.1.0</span>
          <span style={{ color: 'var(--text-4)' }}>Released: 2026-03-18</span>
        </div>
      </div>

      {/* Flavor tabs */}
      <div className="dl-tabs" style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
        <button
          className={cn('dl-tab', flavor === 'light' && 'active')}
          onClick={() => setFlavor('light')}
          style={{
            padding: '6px 14px',
            borderRadius: 'var(--radius)',
            fontSize: '12px',
            border: `1px solid ${flavor === 'light' ? 'var(--accent)' : 'var(--border)'}`,
            background: flavor === 'light' ? 'var(--accent-dim)' : 'transparent',
            color: flavor === 'light' ? 'var(--accent)' : 'var(--text-2)',
            cursor: 'pointer',
            fontFamily: 'inherit',
          }}
        >
          cbom (lightweight ~15MB)
        </button>
        <button
          className={cn('dl-tab', flavor === 'full' && 'active')}
          onClick={() => setFlavor('full')}
          style={{
            padding: '6px 14px',
            borderRadius: 'var(--radius)',
            fontSize: '12px',
            border: `1px solid ${flavor === 'full' ? 'var(--accent)' : 'var(--border)'}`,
            background: flavor === 'full' ? 'var(--accent-dim)' : 'transparent',
            color: flavor === 'full' ? 'var(--accent)' : 'var(--text-2)',
            cursor: 'pointer',
            fontFamily: 'inherit',
          }}
        >
          cbom-full (with OpenGrep ~80MB)
        </button>
      </div>

      {/* Air-gapped note for full */}
      {flavor === 'full' && (
        <div className="alert alert-warn" style={{ marginBottom: '16px' }}>
          cbom-full includes the OpenGrep binary for air-gapped / firewalled environments. No
          internet access required for Pass 2 taint analysis.
        </div>
      )}

      {/* Download cards grid */}
      <div
        className="download-grid"
        style={{
          marginBottom: '16px',
        }}
      >
        {DOWNLOADS.map((dl) => (
          <div
            key={dl.arch}
            className="card"
            style={{
              textAlign: 'center',
              cursor: 'pointer',
              padding: '16px',
            }}
          >
            <div style={{ fontSize: '24px', marginBottom: '6px' }}>{dl.osIcon}</div>
            <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-1)' }}>
              {dl.name}
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-3)', marginTop: '2px' }}>
              {dl.arch}
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-4)', marginTop: '4px' }}>
              {flavor === 'light' ? dl.fileLight : dl.fileFull} &middot;{' '}
              {flavor === 'light' ? dl.sizeLight : dl.sizeFull}
            </div>
          </div>
        ))}
      </div>

      {/* Checksums */}
      <div className="card">
        <div className="card-title">Checksums (SHA-256)</div>
        <div className="code" style={{ fontSize: '10px' }}>
          {CHECKSUMS.map((c) => (
            <div key={c.file}>
              {c.hash} {c.file}
            </div>
          ))}
        </div>
      </div>

      {/* Quick install + Connect CLI */}
      <div className="g2">
        <div className="card">
          <div className="card-title">Quick Install</div>
          <div className="code" style={{ fontSize: '11px' }}>
            <div style={{ color: 'var(--text-4)' }}># Download and extract</div>
            <div>
              curl -sL
              https://github.com/nk-sentinel/cipherradar/releases/latest/download/cbom_0.1.0_darwin_arm64.tar.gz
              | tar xz
            </div>
            <div style={{ marginTop: '8px', color: 'var(--text-4)' }}># Move to PATH</div>
            <div>sudo mv cbom /usr/local/bin/</div>
            <div style={{ marginTop: '8px', color: 'var(--text-4)' }}># Verify</div>
            <div>cbom version</div>
            <div style={{ marginTop: '8px', color: 'var(--text-4)' }}>
              # Install OpenGrep (optional)
            </div>
            <div>cbom install-tools</div>
          </div>
        </div>
        <div className="card">
          <div className="card-title">Connect CLI to Dashboard</div>
          <div className="code" style={{ fontSize: '11px' }}>
            <div style={{ color: 'var(--text-4)' }}>
              # Generate an API key in Settings &gt; API Keys, then:
            </div>
            <div style={{ marginTop: '4px' }}>
              export CRADAR_API_KEY=&quot;your-api-key-here&quot;
            </div>
            <div>
              export CRADAR_API_URL=&quot;https://cipherradar.yourcompany.com/api/v1&quot;
            </div>
            <div style={{ marginTop: '8px', color: 'var(--text-4)' }}>
              # Scan and upload results
            </div>
            <div>cradar scan . --format cyclonedx-json --output cbom.json</div>
            <div>curl -X POST $CRADAR_API_URL/scans \</div>
            <div>&nbsp;&nbsp;-H &quot;Authorization: Bearer $CRADAR_API_KEY&quot; \</div>
            <div>&nbsp;&nbsp;-F &quot;cbom=@cbom.json&quot;</div>
          </div>
        </div>
      </div>

      {/* CI/CD snippets */}
      <div className="g2">
        <div className="card">
          <div className="card-title">GitHub Actions</div>
          <div className="code" style={{ fontSize: '11px' }}>
            <div style={{ color: 'var(--text-4)' }}># .github/workflows/cbom.yml</div>
            <div>- uses: nk-sentinel/cipherradar/deploy/github-action@main</div>
            <div>&nbsp;&nbsp;with:</div>
            <div>&nbsp;&nbsp;&nbsp;&nbsp;format: cyclonedx-json</div>
            <div>&nbsp;&nbsp;&nbsp;&nbsp;upload-sarif: &apos;true&apos;</div>
            <div>&nbsp;&nbsp;&nbsp;&nbsp;policy: policy.cradar.yml</div>
            <div>&nbsp;&nbsp;&nbsp;&nbsp;fail-on: high</div>
          </div>
        </div>
        <div className="card">
          <div className="card-title">GitLab CI</div>
          <div className="code" style={{ fontSize: '11px' }}>
            <div style={{ color: 'var(--text-4)' }}># .gitlab-ci.yml</div>
            <div>include:</div>
            <div>&nbsp;&nbsp;- project: &apos;nk-sentinel/cipherradar&apos;</div>
            <div>&nbsp;&nbsp;&nbsp;&nbsp;ref: main</div>
            <div>
              &nbsp;&nbsp;&nbsp;&nbsp;file: &apos;deploy/gitlab-ci/cbom-scan.gitlab-ci.yml&apos;
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
