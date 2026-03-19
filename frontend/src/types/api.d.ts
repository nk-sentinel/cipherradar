/**
 * API response types — placeholder.
 *
 * In production these will be auto-generated from the backend OpenAPI spec
 * using openapi-typescript. Do NOT hand-write types here once the generator
 * is wired up.
 */

export interface HealthResponse {
  status: string;
  version: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  user: {
    name: string;
    email: string;
    role: string;
    initials: string;
  };
}
