import { test, expect } from '@playwright/test';
import {
  loginAsAdmin,
  checkAccessibility,
  waitForApi,
} from './helpers';

/**
 * Full accessibility audit (D32).
 *
 * Scans every major page with axe-core and asserts zero critical violations.
 */

test.describe('Accessibility audit — all pages', () => {
  test('/login has no critical accessibility violations', async ({ page }) => {
    await page.goto('/login');
    await page.waitForLoadState('networkidle', { timeout: 15_000 });

    const violations = await checkAccessibility(page);
    const critical = violations.filter(
      (v) => v.impact === 'critical' || v.impact === 'serious',
    );
    expect(critical).toEqual([]);
  });

  test('/ (dashboard) has no critical accessibility violations', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    const violations = await checkAccessibility(page);
    const critical = violations.filter(
      (v) => v.impact === 'critical' || v.impact === 'serious',
    );
    expect(critical).toEqual([]);
  });

  test('/scans has no critical accessibility violations', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    await page.goto('/scans');
    await waitForApi(page);

    const violations = await checkAccessibility(page);
    const critical = violations.filter(
      (v) => v.impact === 'critical' || v.impact === 'serious',
    );
    expect(critical).toEqual([]);
  });

  test('/repos/{id}/overview has no critical accessibility violations', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    // Navigate to Repositories -> first repo overview
    await page.getByRole('link', { name: /Repositories/ }).click();
    await expect(page).toHaveURL(/\/repos/);
    await waitForApi(page);

    await page.getByRole('row').nth(1).getByRole('link').first().click();
    await waitForApi(page);

    const violations = await checkAccessibility(page);
    const critical = violations.filter(
      (v) => v.impact === 'critical' || v.impact === 'serious',
    );
    expect(critical).toEqual([]);
  });

  test('/repos/{id}/findings has no critical accessibility violations', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    // Navigate to Repositories -> first repo
    await page.getByRole('link', { name: /Repositories/ }).click();
    await expect(page).toHaveURL(/\/repos/);
    await waitForApi(page);

    await page.getByRole('row').nth(1).getByRole('link').first().click();
    await waitForApi(page);

    // Click on the Findings tab
    const findingsTab = page.getByRole('tab', { name: /findings/i })
      .or(page.locator('.sub-tab', { hasText: /findings/i }));
    if (await findingsTab.first().isVisible({ timeout: 3_000 }).catch(() => false)) {
      await findingsTab.first().click();
      await waitForApi(page);
    }

    const violations = await checkAccessibility(page);
    const critical = violations.filter(
      (v) => v.impact === 'critical' || v.impact === 'serious',
    );
    expect(critical).toEqual([]);
  });

  test('/profile has no critical accessibility violations', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    await page.goto('/profile');
    await waitForApi(page);

    const violations = await checkAccessibility(page);
    const critical = violations.filter(
      (v) => v.impact === 'critical' || v.impact === 'serious',
    );
    expect(critical).toEqual([]);
  });

  test('/admin/users has no critical accessibility violations', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    await page.goto('/admin/users');
    await waitForApi(page);

    const violations = await checkAccessibility(page);
    const critical = violations.filter(
      (v) => v.impact === 'critical' || v.impact === 'serious',
    );
    expect(critical).toEqual([]);
  });

  test('/admin/settings has no critical accessibility violations', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    await page.goto('/admin/settings');
    await waitForApi(page);

    const violations = await checkAccessibility(page);
    const critical = violations.filter(
      (v) => v.impact === 'critical' || v.impact === 'serious',
    );
    expect(critical).toEqual([]);
  });

  test('/admin/integrations has no critical accessibility violations', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    await page.goto('/admin/integrations');
    await waitForApi(page);

    const violations = await checkAccessibility(page);
    const critical = violations.filter(
      (v) => v.impact === 'critical' || v.impact === 'serious',
    );
    expect(critical).toEqual([]);
  });

  test('/requests has no critical accessibility violations', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    await page.goto('/requests');
    await waitForApi(page);

    const violations = await checkAccessibility(page);
    const critical = violations.filter(
      (v) => v.impact === 'critical' || v.impact === 'serious',
    );
    expect(critical).toEqual([]);
  });
});
