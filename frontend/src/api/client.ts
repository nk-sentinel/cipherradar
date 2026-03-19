const API_BASE = '/api/v1';

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
  });

  if (!response.ok) {
    throw new ApiError(response.status, `API error: ${response.statusText}`);
  }

  return response.json() as Promise<T>;
}
