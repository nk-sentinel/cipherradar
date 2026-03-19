/**
 * API configuration.
 *
 * In production the env var VITE_API_BASE_URL should point to the
 * FastAPI backend (e.g. https://cipherradar.company.com/api/v1).
 * During development with MSW the default /api/v1 is intercepted
 * by the mock service worker.
 */
function getApiBaseUrl(): string {
  try {
    const envValue = import.meta.env['VITE_API_BASE_URL'] as string | undefined;
    if (envValue) return envValue;
  } catch {
    // import.meta.env may not be available in test environments
  }
  return '/api/v1';
}

export const API_BASE_URL: string = getApiBaseUrl();
