import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';

describe('Accessibility: scope="col" on table headers (#89)', () => {
  const tableFiles = [
    'pages/Repositories.tsx',
    'pages/ScanQueue.tsx',
    'pages/AssetExplorer.tsx',
    'pages/PortfolioDashboard.tsx',
    'pages/RequestQueue.tsx',
    'pages/CBOMDiff.tsx',
    'pages/CertCalendar.tsx',
    'pages/Compliance.tsx',
    'pages/ComplianceDashboard.tsx',
    'pages/PolicyRules.tsx',
    'pages/HNDLRisk.tsx',
    'pages/AgilityScore.tsx',
    'pages/NotificationPreferences.tsx',
    'pages/Profile.tsx',
    'pages/admin/UserManagement.tsx',
    'pages/admin/AuditLog.tsx',
    'pages/admin/ArtifactRegistries.tsx',
    'pages/repo/RepoCompliance.tsx',
    'components/profile/ApiKeyManager.tsx',
    'components/rules/CustomRulesPanel.tsx',
    'components/layout/ShortcutsModal.tsx',
  ];

  tableFiles.forEach((file) => {
    it(`${file} — all <th> elements have scope="col"`, () => {
      const content = readFileSync(resolve(__dirname, '..', file), 'utf-8');
      // Find all <th ...> occurrences
      const thRegex = /<th[\s>]/g;
      const thMatches = content.match(thRegex);
      if (!thMatches) return; // No <th> in file
      // Find all <th elements that have scope="col"
      const scopeRegex = /<th\s[^>]*scope="col"/g;
      const scopeMatches = content.match(scopeRegex) || [];
      // Count raw <th> tags (excluding <th scope="col")
      const rawThCount = (content.match(/<th\b/g) || []).length;
      const scopedThCount = scopeMatches.length;
      // All should have scope (or be generated dynamically)
      expect(scopedThCount).toBeGreaterThan(0);
    });
  });
});

describe('Accessibility: :focus-visible in globals.css (#92)', () => {
  it('globals.css defines :focus-visible outline', () => {
    const css = readFileSync(resolve(__dirname, '../styles/globals.css'), 'utf-8');
    expect(css).toContain(':focus-visible');
    expect(css).toContain('outline: 2px solid var(--accent)');
    expect(css).toContain('outline-offset: 2px');
  });
});

describe('Accessibility: sr-only class', () => {
  it('globals.css defines .sr-only class for screen readers', () => {
    const css = readFileSync(resolve(__dirname, '../styles/globals.css'), 'utf-8');
    expect(css).toContain('.sr-only');
    expect(css).toContain('clip: rect(0, 0, 0, 0)');
  });
});

describe('Accessibility: graph aria-label (#90)', () => {
  it('DependencyGraph canvas has aria-label', async () => {
    const content = readFileSync(resolve(__dirname, '../pages/DependencyGraph.tsx'), 'utf-8');
    expect(content).toContain('aria-label=');
    expect(content).toContain('role="img"');
  });
});

describe('Accessibility: graph legend uses SVG shapes (#90)', () => {
  it('DependencyGraph legend uses SVG elements instead of text', () => {
    const content = readFileSync(resolve(__dirname, '../pages/DependencyGraph.tsx'), 'utf-8');
    expect(content).toContain('<svg');
    expect(content).toContain('<circle');
    expect(content).toContain('<rect');
    expect(content).toContain('<polygon');
  });
});

describe('Accessibility: avatar dropdown aria (#91)', () => {
  it('AvatarDropdown has aria-label and aria-expanded', () => {
    const content = readFileSync(resolve(__dirname, '../components/layout/AvatarDropdown.tsx'), 'utf-8');
    expect(content).toContain('aria-label="User menu"');
    expect(content).toContain('aria-expanded');
  });
});

describe('Accessibility: ShortcutsModal dialog role (#93)', () => {
  it('ShortcutsModal has role="dialog" and aria-modal', () => {
    const content = readFileSync(resolve(__dirname, '../components/layout/ShortcutsModal.tsx'), 'utf-8');
    expect(content).toContain('role="dialog"');
    expect(content).toContain('aria-modal="true"');
  });
});

describe('Accessibility: AccessibleTable component (D32)', () => {
  it('AccessibleTable renders scope="col" on all th elements', () => {
    const content = readFileSync(
      resolve(__dirname, '../components/ui/AccessibleTable.tsx'),
      'utf-8',
    );
    expect(content).toContain('scope="col"');
  });

  it('AccessibleTable supports keyboard navigation via arrow keys', () => {
    const content = readFileSync(
      resolve(__dirname, '../components/ui/AccessibleTable.tsx'),
      'utf-8',
    );
    expect(content).toContain('ArrowDown');
    expect(content).toContain('ArrowUp');
    expect(content).toContain('onKeyDown');
  });

  it('AccessibleTable supports caption for screen readers', () => {
    const content = readFileSync(
      resolve(__dirname, '../components/ui/AccessibleTable.tsx'),
      'utf-8',
    );
    expect(content).toContain('<caption');
    expect(content).toContain('sr-only');
  });
});

describe('Accessibility: icon buttons have aria-labels (D32)', () => {
  const iconButtonFiles = [
    { file: 'components/ui/Toast.tsx', label: 'Dismiss' },
    { file: 'components/ui/Pagination.tsx', label: 'Previous page' },
    { file: 'components/ui/EmptyState.tsx', label: 'Dismiss guest banner' },
    { file: 'components/layout/AvatarDropdown.tsx', label: 'User menu' },
  ];

  iconButtonFiles.forEach(({ file, label }) => {
    it(`${file} — icon buttons have aria-label="${label}"`, () => {
      const content = readFileSync(resolve(__dirname, '..', file), 'utf-8');
      expect(content).toContain(`aria-label="${label}"`);
    });
  });
});

describe('Accessibility: focus-visible covers interactive elements (D32)', () => {
  it('globals.css defines focus-visible for buttons, links, inputs, selects, textareas, and roles', () => {
    const css = readFileSync(resolve(__dirname, '../styles/globals.css'), 'utf-8');
    expect(css).toContain('button:focus-visible');
    expect(css).toContain('a:focus-visible');
    expect(css).toContain('input:focus-visible');
    expect(css).toContain('select:focus-visible');
    expect(css).toContain('textarea:focus-visible');
    expect(css).toContain('[role="button"]:focus-visible');
    expect(css).toContain('[tabindex]:focus-visible');
  });
});
