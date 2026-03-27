import { test, expect } from '@playwright/test';
import {
  loginAsAdmin,
  checkAccessibility,
  waitForApi,
} from './helpers';

/**
 * Scan lifecycle E2E tests.
 *
 * Covers scan modal, scan queue, scan history, artifact registries,
 * and accessibility for scan-related pages.
 */

test.describe('Scan lifecycle', () => {
  test('admin can open scan modal from dashboard', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    // Click "+ New Scan" button on the dashboard
    await page.getByRole('button', { name: /new scan/i }).click();

    // Verify the scan modal dialog is visible
    const modal = page.getByRole('dialog');
    await expect(modal).toBeVisible({ timeout: 5_000 });

    // Verify all 3 tabs are present: Repository, Container, Artifact
    await expect(
      modal.getByRole('tab', { name: /repository/i }),
    ).toBeVisible();
    await expect(
      modal.getByRole('tab', { name: /container/i }),
    ).toBeVisible();
    await expect(
      modal.getByRole('tab', { name: /artifact/i }),
    ).toBeVisible();
  });

  test('scan queue page loads with filters', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    // Navigate to /scans
    await page.goto('/scans');
    await waitForApi(page);

    // Verify scan queue table is visible
    await expect(
      page.getByRole('table').first(),
    ).toBeVisible({ timeout: 10_000 });

    // Verify status filter dropdown
    const statusFilter = page.getByRole('combobox', { name: /status/i })
      .or(page.getByLabel(/status/i))
      .or(page.getByRole('button', { name: /status/i }));
    await expect(statusFilter.first()).toBeVisible();

    // Verify project filter dropdown
    const projectFilter = page.getByRole('combobox', { name: /project/i })
      .or(page.getByLabel(/project/i))
      .or(page.getByRole('button', { name: /project/i }));
    await expect(projectFilter.first()).toBeVisible();

    // Verify trigger filter dropdown
    const triggerFilter = page.getByRole('combobox', { name: /trigger/i })
      .or(page.getByLabel(/trigger/i))
      .or(page.getByRole('button', { name: /trigger/i }));
    await expect(triggerFilter.first()).toBeVisible();
  });

  test('scan history shows environment badges', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    // Navigate to Repositories
    await page.getByRole('link', { name: /Repositories/ }).click();
    await expect(page).toHaveURL(/\/repos/);
    await waitForApi(page);

    // Click into the first repository to view its scan history
    await page.getByRole('row').nth(1).getByRole('link').first().click();
    await waitForApi(page);

    // Navigate to scan history tab if present
    const historyTab = page.getByRole('tab', { name: /scan history|history|scans/i });
    if (await historyTab.isVisible({ timeout: 3_000 }).catch(() => false)) {
      await historyTab.click();
      await waitForApi(page);
    }

    // Verify scan rows exist in the history
    const scanRows = page.getByRole('row');
    await expect(scanRows.nth(1)).toBeVisible({ timeout: 10_000 });

    // Each scan row should have an environment badge or a dash placeholder
    const firstDataRow = scanRows.nth(1);
    const envBadge = firstDataRow.getByText(/production|staging|development|ci|—/i);
    await expect(envBadge.first()).toBeVisible();
  });

  test('artifact registries page loads for admin', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    // Navigate to /admin/registries
    await page.goto('/admin/registries');
    await waitForApi(page);

    // Verify the page heading is visible
    await expect(
      page.getByRole('heading', { name: /registries|artifact registries/i }).first(),
    ).toBeVisible({ timeout: 10_000 });

    // Verify the registries table renders
    await expect(
      page.getByRole('table').first(),
    ).toBeVisible({ timeout: 10_000 });
  });

  test('scan pages have no accessibility violations', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    // Check /scans page accessibility
    await page.goto('/scans');
    await waitForApi(page);

    const scansViolations = await checkAccessibility(page);
    expect(scansViolations).toEqual([]);

    // Check /admin/registries page accessibility
    await page.goto('/admin/registries');
    await waitForApi(page);

    const registriesViolations = await checkAccessibility(page);
    expect(registriesViolations).toEqual([]);
  });
});
