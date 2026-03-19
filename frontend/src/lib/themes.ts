export type Theme = 'radar' | 'crystal' | 'sentinel';

const STORAGE_KEY = 'cipherradar-theme';
const DEFAULT_THEME: Theme = 'radar';

export const THEME_LABELS: Record<Theme, string> = {
  radar: 'Radar',
  crystal: 'Crystal',
  sentinel: 'Sentinel',
};

export const THEME_DESCRIPTIONS: Record<Theme, string> = {
  radar: 'Dark theme — primary dashboard experience',
  crystal: 'Light theme — high-contrast for readability',
  sentinel: 'Blue-tinted dark theme — alternative dark option',
};

export function applyTheme(theme: Theme): void {
  document.body.className = `theme-${theme}`;
  try { localStorage.setItem(STORAGE_KEY, theme); } catch { /* SSR/test env */ }
}

export function getStoredTheme(): Theme {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === 'radar' || stored === 'crystal' || stored === 'sentinel') {
      return stored;
    }
  } catch { /* SSR/test env */ }
  return DEFAULT_THEME;
}
