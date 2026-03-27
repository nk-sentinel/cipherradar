import { test, expect } from '@playwright/test';
import {
  loginAsAdmin,
  loginAsDeveloper,
  checkAccessibility,
  waitForApi,
} from './helpers';

/**
 * User & Auth E2E tests.
 *
 * Covers login page elements, SSO absence, user management,
 * profile/API-key section, and accessibility.
 */

test.describe('User & Auth', () => {
  test('login page shows forgot password link', async ({ page }) => {
    await page.goto('/login');

    await expect(
      page.getByRole('link', { name: /forgot password/i }),
    ).toBeVisible();
  });

  test('SSO buttons are not visible on login page', async ({ page }) => {
    await page.goto('/login');

    // Verify no GitHub SSO button
    await expect(
      page.getByRole('button', { name: /github/i }),
    ).not.toBeVisible();

    // Verify no SAML SSO button
    await expect(
      page.getByRole('button', { name: /saml/i }),
    ).not.toBeVisible();

    // Verify no generic SSO button
    await expect(
      page.getByRole('button', { name: /sso/i }),
    ).not.toBeVisible();
  });

  test('admin can see user management page', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    // Navigate to user management
    await page.goto('/admin/users');
    await waitForApi(page);

    // Verify the page heading is visible
    await expect(
      page.getByRole('heading', { name: /users|user management/i }).first(),
    ).toBeVisible({ timeout: 10_000 });

    // Verify users table renders
    await expect(
      page.getByRole('table').first(),
    ).toBeVisible({ timeout: 10_000 });
  });

  test('profile page shows API key section', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    // Navigate to profile page
    await page.goto('/profile');
    await waitForApi(page);

    // Verify the API key section heading or label is visible
    const apiKeySection = page.getByRole('heading', { name: /api key/i })
      .or(page.getByText(/api key/i));
    await expect(apiKeySection.first()).toBeVisible({ timeout: 10_000 });
  });

  test('profile page has no accessibility violations', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    await page.goto('/profile');
    await waitForApi(page);

    const violations = await checkAccessibility(page);
    expect(violations).toEqual([]);
  });

  test('user management has no accessibility violations', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    await page.goto('/admin/users');
    await waitForApi(page);

    const violations = await checkAccessibility(page);
    expect(violations).toEqual([]);
  });
});
