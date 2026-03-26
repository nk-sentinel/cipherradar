import { test, expect } from '@playwright/test';
import {
  login,
  checkAccessibility,
  waitForApi,
} from './helpers';

/**
 * Finding workflow E2E tests.
 *
 * Test users:
 *   security-eng@cipherradar.local  — security_engineer (SE)
 *   developer@cipherradar.local     — developer (DEV)
 *   admin@cipherradar.local         — org_admin (also has SM capabilities)
 *   team-lead@cipherradar.local     — team_manager (TM)
 */

const SE_EMAIL = 'security-eng@cipherradar.local';
const DEV_EMAIL = 'developer@cipherradar.local';
const SM_EMAIL = 'admin@cipherradar.local';
const TM_EMAIL = 'team-lead@cipherradar.local';
const PASSWORD = 'password';

test.describe('Finding workflow', () => {
  test('SE can view findings with status filter', async ({ page }) => {
    await login(page, SE_EMAIL, PASSWORD);
    await waitForApi(page);

    // Navigate to Repositories, then into the first repo's findings
    await page.getByRole('link', { name: /Repositories/ }).click();
    await expect(page).toHaveURL(/\/repos/);
    await waitForApi(page);

    // Click the first repository to go to its detail / findings page
    const firstRepo = page.getByRole('link', { name: /findings/i }).first();
    // Fallback: if there is a table row, click into the first repo
    if (await firstRepo.isVisible({ timeout: 3_000 }).catch(() => false)) {
      await firstRepo.click();
    } else {
      // Click the first row link in the repo table
      await page.getByRole('row').nth(1).getByRole('link').first().click();
    }
    await waitForApi(page);

    // Verify the status filter bar is visible with at least one status count
    const statusFilter = page.getByRole('group', { name: /status/i })
      .or(page.getByRole('tablist'))
      .or(page.getByLabel(/status filter/i));
    await expect(statusFilter.first()).toBeVisible({ timeout: 10_000 });

    // Verify we see at least one status count badge (e.g. "Open", "In Review")
    const openBadge = page.getByText(/open/i).first();
    await expect(openBadge).toBeVisible();
  });

  test('SE can change finding status to In Review', async ({ page }) => {
    await login(page, SE_EMAIL, PASSWORD);
    await waitForApi(page);

    // Navigate to Repositories -> first repo -> findings
    await page.getByRole('link', { name: /Repositories/ }).click();
    await waitForApi(page);
    await page.getByRole('row').nth(1).getByRole('link').first().click();
    await waitForApi(page);

    // Click the first finding row to open its detail
    const findingRow = page.getByRole('row').nth(1);
    await findingRow.getByRole('link').first().click();
    await waitForApi(page);

    // Change status via dropdown/select
    const statusDropdown = page.getByRole('combobox', { name: /status/i })
      .or(page.getByLabel(/status/i))
      .or(page.getByRole('button', { name: /status/i }));
    await statusDropdown.first().click();

    // Select "In Review" from the dropdown options
    await page.getByRole('option', { name: /in review/i })
      .or(page.getByText(/in review/i))
      .first()
      .click();

    // Verify the badge/status updates to reflect the new status
    await expect(
      page.getByText(/in review/i).first(),
    ).toBeVisible({ timeout: 5_000 });
  });

  test('DEV can request FP review', async ({ page }) => {
    await login(page, DEV_EMAIL, PASSWORD);
    await waitForApi(page);

    // Navigate to Repositories -> first repo -> findings
    await page.getByRole('link', { name: /Repositories/ }).click();
    await waitForApi(page);
    await page.getByRole('row').nth(1).getByRole('link').first().click();
    await waitForApi(page);

    // Click first finding to open detail
    await page.getByRole('row').nth(1).getByRole('link').first().click();
    await waitForApi(page);

    // Click "Request FP Review" button
    await page.getByRole('button', { name: /request fp review|false positive/i }).click();

    // Fill justification in the dialog/form
    const justificationField = page.getByLabel(/justification|reason/i)
      .or(page.getByRole('textbox', { name: /justification|reason/i }))
      .or(page.getByPlaceholder(/justification|reason|why/i));
    await justificationField.first().fill(
      'This is a test string used in unit tests, not a real cryptographic key.',
    );

    // Submit the FP review request
    await page.getByRole('button', { name: /submit|request/i }).last().click();

    // Verify success toast notification
    await expect(
      page.getByText(/request submitted|false positive.*submitted|review requested/i).first(),
    ).toBeVisible({ timeout: 10_000 });
  });

  test('SM can approve FP request from queue', async ({ page }) => {
    await login(page, SM_EMAIL, PASSWORD);
    await waitForApi(page);

    // Navigate to the requests queue page
    await page.goto('/requests');
    await waitForApi(page);

    // Verify we are on the requests page
    await expect(
      page.getByRole('heading', { name: /requests|review queue/i }).first(),
    ).toBeVisible({ timeout: 10_000 });

    // Click approve on the first pending request
    const approveButton = page.getByRole('button', { name: /approve/i }).first();
    await expect(approveButton).toBeVisible({ timeout: 5_000 });
    await approveButton.click();

    // Verify success toast notification
    await expect(
      page.getByText(/approved|request approved/i).first(),
    ).toBeVisible({ timeout: 10_000 });
  });

  test('TM can bulk assign findings', async ({ page }) => {
    await login(page, TM_EMAIL, PASSWORD);
    await waitForApi(page);

    // Navigate to Repositories -> first repo -> findings
    await page.getByRole('link', { name: /Repositories/ }).click();
    await waitForApi(page);
    await page.getByRole('row').nth(1).getByRole('link').first().click();
    await waitForApi(page);

    // Select 2 finding checkboxes for bulk action
    const checkboxes = page.getByRole('checkbox');
    const firstCheckbox = checkboxes.nth(0);
    const secondCheckbox = checkboxes.nth(1);

    await firstCheckbox.check();
    await secondCheckbox.check();

    // Click the bulk "Assign" action in the bulk action bar
    const assignButton = page.getByRole('button', { name: /assign/i }).first();
    await expect(assignButton).toBeVisible({ timeout: 5_000 });
    await assignButton.click();

    // Select a user from the assignment dialog
    const userOption = page.getByRole('option').first()
      .or(page.getByRole('listbox').getByRole('option').first())
      .or(page.getByRole('combobox', { name: /assign|user/i }));
    if (await userOption.first().isVisible({ timeout: 3_000 }).catch(() => false)) {
      await userOption.first().click();
    } else {
      // Fallback: type in a user search and pick from list
      const userSearch = page.getByRole('combobox').first()
        .or(page.getByPlaceholder(/search.*user|assign to/i).first());
      await userSearch.first().fill('developer');
      await page.getByRole('option').first().click();
    }

    // Confirm the assignment
    const confirmButton = page.getByRole('button', { name: /confirm|assign/i }).last();
    await confirmButton.click();

    // Verify success notification
    await expect(
      page.getByText(/assigned|findings assigned/i).first(),
    ).toBeVisible({ timeout: 10_000 });
  });

  test('findings page has no accessibility violations', async ({ page }) => {
    await login(page, SE_EMAIL, PASSWORD);
    await waitForApi(page);

    // Navigate to Repositories -> first repo -> findings
    await page.getByRole('link', { name: /Repositories/ }).click();
    await waitForApi(page);
    await page.getByRole('row').nth(1).getByRole('link').first().click();
    await waitForApi(page);

    const violations = await checkAccessibility(page);
    expect(violations).toEqual([]);
  });
});
