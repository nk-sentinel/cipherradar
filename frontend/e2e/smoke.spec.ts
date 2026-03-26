import { test, expect } from '@playwright/test';
import {
  login,
  loginAsAdmin,
  checkAccessibility,
  waitForApi,
} from './helpers';

test.describe('Smoke tests', () => {
  test('login page loads', async ({ page }) => {
    await page.goto('/login');

    await expect(page.getByLabel('Email')).toBeVisible();
    await expect(page.getByLabel('Password')).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Sign In' }),
    ).toBeVisible();
    await expect(page.getByText('CipherRadar')).toBeVisible();
    await expect(
      page.getByText('Cryptographic Asset Intelligence Platform'),
    ).toBeVisible();
  });

  test('admin can login and see dashboard', async ({ page }) => {
    await loginAsAdmin(page);

    await expect(
      page.getByRole('heading', { name: 'Dashboard' }),
    ).toBeVisible();
  });

  test('sidebar navigation works', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    // Navigate to Asset Explorer via sidebar
    await page.getByRole('link', { name: /Asset Explorer/ }).click();
    await expect(page).toHaveURL(/\/assets/);

    // Navigate to Repositories via sidebar
    await page.getByRole('link', { name: /Repositories/ }).click();
    await expect(page).toHaveURL(/\/repos/);

    // Navigate back to Dashboard
    await page.getByRole('link', { name: /Dashboard/ }).click();
    await expect(page).toHaveURL('/');
  });

  test('unauthorized redirect to login', async ({ page }) => {
    // Navigate directly to an authenticated route without logging in
    await page.goto('/admin/users');

    // Should be redirected to login page
    await expect(page).toHaveURL(/\/login/);
    await expect(page.getByLabel('Email')).toBeVisible();
  });

  test('login page has no accessibility violations', async ({ page }) => {
    await page.goto('/login');
    await expect(page.getByLabel('Email')).toBeVisible();

    const violations = await checkAccessibility(page);
    expect(violations).toEqual([]);
  });

  test('dashboard has no accessibility violations', async ({ page }) => {
    await loginAsAdmin(page);
    await waitForApi(page);

    const violations = await checkAccessibility(page);
    expect(violations).toEqual([]);
  });
});
