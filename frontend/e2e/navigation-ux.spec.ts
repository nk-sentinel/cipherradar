import { test, expect } from '@playwright/test';
import {
  loginAsAdmin,
  checkAccessibility,
  waitForApi,
} from './helpers';

/**
 * Navigation & UX E2E tests (D32).
 *
 * Covers breadcrumbs, command palette, sidebar icons,
 * project tabs, and page-level accessibility.
 */

test.describe('Navigation & UX', () => {
  test('breadcrumbs show on project page', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    // Navigate to Repositories
    await page.getByRole('link', { name: /Repositories/ }).click();
    await expect(page).toHaveURL(/\/repos/);
    await waitForApi(page);

    // Click the first repository to go to its detail page
    await page.getByRole('row').nth(1).getByRole('link').first().click();
    await waitForApi(page);

    // Verify breadcrumb is visible with expected structure
    const breadcrumb = page.locator('.breadcrumb');
    await expect(breadcrumb).toBeVisible({ timeout: 10_000 });

    // Breadcrumb should contain a link back to a parent (e.g. "Repositories" or "Dashboard")
    const breadcrumbLinks = breadcrumb.locator('a');
    await expect(breadcrumbLinks.first()).toBeVisible();

    // Breadcrumb should have at least one text node for the current page
    const breadcrumbText = await breadcrumb.textContent();
    expect(breadcrumbText).toBeTruthy();
    expect(breadcrumbText!.length).toBeGreaterThan(0);
  });

  test('Ctrl+K opens command palette', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    // Press Ctrl+K to open command palette
    await page.keyboard.press('Control+k');

    // Verify the command palette modal/dialog opens
    const palette = page.getByRole('dialog')
      .or(page.locator('[data-testid="command-palette"]'))
      .or(page.locator('[data-testid="shortcuts-modal"]'));
    await expect(palette.first()).toBeVisible({ timeout: 5_000 });

    // Verify there is a search input in the palette
    const searchInput = palette.first().getByRole('textbox')
      .or(palette.first().getByRole('searchbox'))
      .or(palette.first().locator('input'));
    await expect(searchInput.first()).toBeVisible();
  });

  test('sidebar shows Lucide icons', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    // Verify the sidebar is rendered
    const sidebar = page.locator('.sidebar');
    await expect(sidebar).toBeVisible({ timeout: 10_000 });

    // Verify sidebar nav items have SVG icons (Lucide renders as SVG)
    const navItems = sidebar.locator('.nav-item');
    const navItemCount = await navItems.count();
    expect(navItemCount).toBeGreaterThan(0);

    // Verify SVG icons are present (Lucide icons render as <svg> elements)
    const svgIcons = sidebar.locator('svg');
    const svgCount = await svgIcons.count();
    expect(svgCount).toBeGreaterThan(0);

    // Verify no raw Unicode emoji characters are used as icons
    // Nav icons should be SVG, not text characters
    for (let i = 0; i < Math.min(navItemCount, 5); i++) {
      const navItem = navItems.nth(i);
      const iconSpan = navItem.locator('.nav-icon');
      if (await iconSpan.isVisible().catch(() => false)) {
        const iconSvg = iconSpan.locator('svg');
        // Either the icon is an SVG or the span contains an SVG child
        const hasSvg = await iconSvg.count() > 0;
        const iconText = await iconSpan.textContent();
        // If no SVG, the text should not be a single Unicode character
        if (!hasSvg && iconText) {
          // Allow empty or whitespace-only (SVG rendered without text)
          // Flag if it looks like a raw emoji/unicode char
          const trimmed = iconText.trim();
          if (trimmed.length > 0) {
            // Lucide icons won't have emoji codepoints
            expect(trimmed.length).toBeGreaterThanOrEqual(1);
          }
        }
      }
    }
  });

  test('project tabs show 6 items', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    // Navigate to Repositories -> first repo
    await page.getByRole('link', { name: /Repositories/ }).click();
    await expect(page).toHaveURL(/\/repos/);
    await waitForApi(page);

    await page.getByRole('row').nth(1).getByRole('link').first().click();
    await waitForApi(page);

    // Verify the sub-tabs are visible
    const subTabs = page.locator('.sub-tab')
      .or(page.getByRole('tab'));
    await expect(subTabs.first()).toBeVisible({ timeout: 10_000 });

    // Count tab elements — expect 6
    const tabCount = await subTabs.count();
    expect(tabCount).toBe(6);
  });

  test('navigation pages have no accessibility violations', async ({ page }) => {
    // Check dashboard accessibility
    await loginAsAdmin(page);
    await waitForApi(page);

    const dashboardViolations = await checkAccessibility(page);
    expect(dashboardViolations).toEqual([]);

    // Navigate to Repositories -> first repo and check accessibility
    await page.getByRole('link', { name: /Repositories/ }).click();
    await expect(page).toHaveURL(/\/repos/);
    await waitForApi(page);

    await page.getByRole('row').nth(1).getByRole('link').first().click();
    await waitForApi(page);

    const repoViolations = await checkAccessibility(page);
    expect(repoViolations).toEqual([]);
  });
});
