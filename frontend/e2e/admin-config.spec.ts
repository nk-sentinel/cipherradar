import { test, expect } from '@playwright/test';
import {
  loginAsAdmin,
  checkAccessibility,
  waitForApi,
} from './helpers';

/**
 * Admin Configuration E2E tests.
 *
 * Covers integration management, LLM config, policy rules,
 * audit log, and accessibility for admin pages.
 */

test.describe('Admin config', () => {
  test('integration management page loads', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    // Navigate to integration management
    await page.goto('/admin/integrations');
    await waitForApi(page);

    // Verify the page heading is visible
    await expect(
      page.getByRole('heading', { name: /integrations|integration management/i }).first(),
    ).toBeVisible({ timeout: 10_000 });

    // Verify provider cards are visible (GitHub, GitLab, Bitbucket)
    const githubCard = page.getByText(/github/i).first();
    await expect(githubCard).toBeVisible({ timeout: 10_000 });

    const gitlabCard = page.getByText(/gitlab/i).first();
    await expect(gitlabCard).toBeVisible();

    const bitbucketCard = page.getByText(/bitbucket/i).first();
    await expect(bitbucketCard).toBeVisible();
  });

  test('LLM config page loads', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    // Navigate to LLM configuration
    await page.goto('/admin/llm-config');
    await waitForApi(page);

    // Verify the page heading is visible
    await expect(
      page.getByRole('heading', { name: /llm|ai|language model/i }).first(),
    ).toBeVisible({ timeout: 10_000 });

    // Verify provider selector is present (dropdown or select)
    const providerSelector = page.getByRole('combobox', { name: /provider/i })
      .or(page.getByLabel(/provider/i))
      .or(page.getByRole('button', { name: /provider/i }));
    await expect(providerSelector.first()).toBeVisible({ timeout: 10_000 });
  });

  test('policy rules page shows lock icons', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    // Navigate to policy rules page
    await page.goto('/admin/policy');
    await waitForApi(page);

    // Verify policy rules heading is visible
    await expect(
      page.getByRole('heading', { name: /policy|rules/i }).first(),
    ).toBeVisible({ timeout: 10_000 });

    // Verify lock icons are visible for org admin
    // Lock icons may be buttons, SVG icons, or span elements
    const lockIcon = page.getByRole('button', { name: /lock/i })
      .or(page.locator('[data-testid*="lock"]'))
      .or(page.locator('[aria-label*="lock" i]'))
      .or(page.locator('.lock-icon'))
      .or(page.locator('svg[class*="lock"]'));
    await expect(lockIcon.first()).toBeVisible({ timeout: 10_000 });
  });

  test('audit log page has filters', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    // Navigate to audit log
    await page.goto('/admin/audit-log');
    await waitForApi(page);

    // Verify audit log heading is visible
    await expect(
      page.getByRole('heading', { name: /audit log/i }).first(),
    ).toBeVisible({ timeout: 10_000 });

    // Verify date range filter
    const dateFilter = page.getByLabel(/date/i)
      .or(page.getByRole('textbox', { name: /date/i }))
      .or(page.getByPlaceholder(/date/i));
    await expect(dateFilter.first()).toBeVisible({ timeout: 10_000 });

    // Verify user filter dropdown
    const userFilter = page.getByRole('combobox', { name: /user/i })
      .or(page.getByLabel(/user/i))
      .or(page.getByRole('button', { name: /user/i }));
    await expect(userFilter.first()).toBeVisible({ timeout: 10_000 });

    // Verify action type filter dropdown
    const actionFilter = page.getByRole('combobox', { name: /action/i })
      .or(page.getByLabel(/action/i))
      .or(page.getByRole('button', { name: /action/i }));
    await expect(actionFilter.first()).toBeVisible({ timeout: 10_000 });
  });

  test('admin pages have no accessibility violations', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    // Check /admin/integrations accessibility
    await page.goto('/admin/integrations');
    await waitForApi(page);
    const integrationsViolations = await checkAccessibility(page);
    expect(integrationsViolations).toEqual([]);

    // Check /admin/llm-config accessibility
    await page.goto('/admin/llm-config');
    await waitForApi(page);
    const llmViolations = await checkAccessibility(page);
    expect(llmViolations).toEqual([]);

    // Check /admin/policy accessibility
    await page.goto('/admin/policy');
    await waitForApi(page);
    const policyViolations = await checkAccessibility(page);
    expect(policyViolations).toEqual([]);

    // Check /admin/audit-log accessibility
    await page.goto('/admin/audit-log');
    await waitForApi(page);
    const auditViolations = await checkAccessibility(page);
    expect(auditViolations).toEqual([]);
  });
});
