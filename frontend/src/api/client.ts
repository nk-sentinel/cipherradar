import { API_BASE_URL } from './config.ts';

const API_BASE = API_BASE_URL;

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  body?: unknown;
  headers?: Record<string, string>;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

// Track whether a refresh is already in progress to avoid concurrent refreshes
let refreshPromise: Promise<string | null> | null = null;

/**
 * Attempt to refresh the access token using the httpOnly refresh cookie.
 * The cookie is automatically sent by the browser to /api/v1/auth/refresh.
 * Returns the new access token or null if refresh failed.
 */
async function refreshAccessToken(): Promise<string | null> {
  try {
    const response = await fetch(`${API_BASE}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include', // sends httpOnly cookie
      body: JSON.stringify({}),
    });

    if (!response.ok) {
      return null; // refresh failed — session expired
    }

    const data = (await response.json()) as { accessToken?: string };
    const newToken = data.accessToken ?? null;

    if (newToken) {
      // Update stored token
      sessionStorage.setItem('cipherradar-token', newToken);
    }

    return newToken;
  } catch {
    return null;
  }
}

/**
 * Main API client. Handles:
 * - Authorization header from sessionStorage
 * - Auto-refresh on 401 (token expired)
 * - Redirect to login if refresh also fails
 */
export async function apiClient<T>(
  endpoint: string,
  options: RequestOptions = {},
): Promise<T> {
  const { method = 'GET', body, headers = {} } = options;

  const token = sessionStorage.getItem('cipherradar-token');

  const requestHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
    ...headers,
  };

  if (token) {
    requestHeaders['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    method,
    headers: requestHeaders,
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'include', // send cookies for CORS
  });

  // If 401, try to refresh the token and retry once
  if (response.status === 401 && token) {
    // Deduplicate concurrent refresh attempts
    if (!refreshPromise) {
      refreshPromise = refreshAccessToken().finally(() => {
        refreshPromise = null;
      });
    }

    const newToken = await refreshPromise;

    if (newToken) {
      // Retry the original request with the new token
      const retryHeaders = { ...requestHeaders, Authorization: `Bearer ${newToken}` };
      const retryResponse = await fetch(`${API_BASE}${endpoint}`, {
        method,
        headers: retryHeaders,
        body: body ? JSON.stringify(body) : undefined,
        credentials: 'include',
      });

      if (!retryResponse.ok) {
        throw new ApiError(retryResponse.status, `API error: ${retryResponse.statusText}`);
      }

      return retryResponse.json() as Promise<T>;
    }

    // Refresh failed — session expired. Redirect to login.
    sessionStorage.removeItem('cipherradar-token');
    sessionStorage.removeItem('cipherradar-user');
    if (window.location.pathname !== '/login') {
      window.location.href = '/login?expired=1';
    }
    throw new ApiError(401, 'Session expired. Please log in again.');
  }

  if (!response.ok) {
    throw new ApiError(response.status, `API error: ${response.statusText}`);
  }

  return response.json() as Promise<T>;
}
