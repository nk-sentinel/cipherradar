import { test, expect } from '@playwright/test';
import {
  loginAsAdmin,
  checkAccessibility,
  waitForApi,
} from './helpers';

/**
 * Portfolio views E2E tests (Plan 7.5).
 *
 * Validates certificate tracker, compliance/PQC migration pages,
 * and accessibility on portfolio views.
 */

test.describe('Portfolio views', () => {
  test('certificate tracker page loads', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    await page.goto('/certificate-tracker');
    await waitForApi(page);

    // Verify certificate tracker heading is visible
    await expect(
      page.getByRole('heading', { name: /certificate/i }),
    ).toBeVisible({ timeout: 10_000 });

    // Verify a data table is rendered
    await expect(page.getByRole('table')).toBeVisible();
  });

  test('certificate badges show colors', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    await page.goto('/certificate-tracker');
    await waitForApi(page);

    // Verify at least one status badge exists with green/amber/red color semantics.
    // Badges use data-status or CSS class conventions for color.
    const greenBadge = page.locator(
      '[data-status="valid"], [data-status="active"], .badge-green, .badge-success, [class*="green"], [class*="success"]',
    );
    const amberBadge = page.locator(
      '[data-status="expiring"], [data-status="warning"], .badge-amber, .badge-warning, [class*="amber"], [class*="warning"], [class*="yellow"]',
    );
    const redBadge = page.locator(
      '[data-status="expired"], [data-status="critical"], .badge-red, .badge-danger, .badge-destructive, [class*="red"], [class*="danger"], [class*="destructive"]',
    );

    // At least one of the three badge types should be present on the page
    const hasGreen = await greenBadge.first().isVisible().catch(() => false);
    const hasAmber = await amberBadge.first().isVisible().catch(() => false);
    const hasRed = await redBadge.first().isVisible().catch(() => false);

    expect(
      hasGreen || hasAmber || hasRed,
    ).toBe(true);
  });

  test('compliance page shows PQC migration section', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    await page.goto('/compliance');
    await waitForApi(page);

    // Verify the PQC Migration heading or section exists
    await expect(
      page.getByRole('heading', { name: /PQC Migration/i })
        .or(page.locator('text=PQC Migration')),
    ).toBeVisible({ timeout: 10_000 });
  });

  test('PQC progress bars render', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    await page.goto('/compliance');
    await waitForApi(page);

    // Progress bars can be <progress>, role="progressbar", or chart elements
    const progressBars = page.getByRole('progressbar')
      .or(page.locator('progress'))
      .or(page.locator('[class*="progress"]'))
      .or(page.locator('[data-testid*="progress"]'));

    await expect(progressBars.first()).toBeVisible({ timeout: 10_000 });
  });

  test('portfolio pages have no accessibility violations', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    // Check /certificate-tracker
    await page.goto('/certificate-tracker');
    await waitForApi(page);

    const certViolations = await checkAccessibility(page);
    const certCritical = certViolations.filter(
      (v) => v.impact === 'critical' || v.impact === 'serious',
    );
    expect(certCritical).toEqual([]);

    // Check /compliance
    await page.goto('/compliance');
    await waitForApi(page);

    const complianceViolations = await checkAccessibility(page);
    const complianceCritical = complianceViolations.filter(
      (v) => v.impact === 'critical' || v.impact === 'serious',
    );
    expect(complianceCritical).toEqual([]);
  });
});
