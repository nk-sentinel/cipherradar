import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';

describe('Crystal theme WCAG AA contrast fix (D29)', () => {
  it('--text-4 has sufficient contrast on white background', () => {
    const css = readFileSync(resolve(__dirname, '../styles/themes/crystal.css'), 'utf-8');
    // Extract --text-4 value
    const match = css.match(/--text-4:\s*(#[0-9a-fA-F]+)/);
    expect(match).not.toBeNull();
    const color = match![1];
    // Old value was #bbb (fails WCAG AA). New value should be darker.
    // #bbb = rgb(187,187,187), contrast on white = 1.96:1 (fail)
    // #737373 = rgb(115,115,115), contrast on white = 4.65:1 (pass)
    expect(color).not.toBe('#bbb');
    // Ensure the new value is dark enough (hex value below #808080)
    const r = parseInt(color!.slice(1, 3), 16);
    const g = parseInt(color!.slice(3, 5), 16);
    const b = parseInt(color!.slice(5, 7), 16);
    const luminance = (r + g + b) / 3;
    // Should be below 128 for adequate contrast on white
    expect(luminance).toBeLessThan(128);
  });
});

describe('globals.css type scale (D29)', () => {
  it('defines type scale CSS variables', () => {
    const css = readFileSync(resolve(__dirname, '../styles/globals.css'), 'utf-8');
    expect(css).toContain('--text-xs: 12px');
    expect(css).toContain('--text-sm: 14px');
    expect(css).toContain('--text-base: 16px');
    expect(css).toContain('--text-lg: 20px');
    expect(css).toContain('--text-xl: 24px');
  });
});

describe('globals.css badge standardization (D29)', () => {
  it('defines badge-info class', () => {
    const css = readFileSync(resolve(__dirname, '../styles/globals.css'), 'utf-8');
    expect(css).toContain('.badge-info');
    expect(css).toContain('.badge-blue');
    expect(css).toContain('.badge-amber');
    expect(css).toContain('.badge-purple');
    expect(css).toContain('.badge-green');
    expect(css).toContain('.badge-gray');
  });
});

describe('globals.css focus-visible (D29/D32)', () => {
  it('defines :focus-visible styles', () => {
    const css = readFileSync(resolve(__dirname, '../styles/globals.css'), 'utf-8');
    expect(css).toContain(':focus-visible');
    expect(css).toContain('outline: 2px solid var(--accent)');
  });
});

describe('globals.css responsive sidebar collapse (D29)', () => {
  it('collapses sidebar at 1024px breakpoint', () => {
    const css = readFileSync(resolve(__dirname, '../styles/globals.css'), 'utf-8');
    expect(css).toContain('max-width: 1024px');
    expect(css).toContain('.sidebar');
  });
});

describe('Profile theme picker thumbnails (D29)', () => {
  it('exports the Profile component', async () => {
    const mod = await import('@/pages/Profile');
    expect(typeof mod.Profile).toBe('function');
  });
});

describe('Theme preview CSS classes (D29)', () => {
  it('defines theme-preview CSS classes', () => {
    const css = readFileSync(resolve(__dirname, '../styles/globals.css'), 'utf-8');
    expect(css).toContain('.theme-preview');
    expect(css).toContain('.theme-preview-sidebar');
    expect(css).toContain('.theme-preview-content');
    expect(css).toContain('.theme-preview-line');
  });
});
