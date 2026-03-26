import { type Page, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

/**
 * Fill the login form and submit. Waits for navigation to the dashboard.
 */
export async function login(
  page: Page,
  email: string,
  password: string,
): Promise<void> {
  await page.goto('/login');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button', { name: 'Sign In' }).click();

  // Wait for dashboard heading to confirm successful login
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({
    timeout: 10_000,
  });
}

/**
 * Login as the seeded org_admin user.
 */
export async function loginAsAdmin(page: Page): Promise<void> {
  await login(page, 'admin@cipherradar.local', 'password');
}

/**
 * Login as the seeded developer user.
 */
export async function loginAsDeveloper(page: Page): Promise<void> {
  await login(page, 'developer@cipherradar.local', 'password');
}

/**
 * Run an axe-core accessibility scan and return any violations found.
 */
export async function checkAccessibility(
  page: Page,
): Promise<import('axe-core').Result[]> {
  const results = await new AxeBuilder({ page }).analyze();
  return results.violations;
}

/**
 * Wait for in-flight API requests to settle after page load.
 * Uses networkidle to detect when the initial burst of API calls has finished.
 */
export async function waitForApi(page: Page): Promise<void> {
  await page.waitForLoadState('networkidle', { timeout: 15_000 });
}
