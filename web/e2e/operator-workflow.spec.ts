import { readFile } from 'node:fs/promises';
import { test, expect, signIn, finishedRun } from './fixtures';

test('scoped investigations can be reopened, compared, exported, and deleted', async ({ page }) => {
  await signIn(page);
  await page.getByLabel(/demo-log/).uncheck();
  await page.getByLabel('Investigation').selectOption('firmware triage');
  const firstStarted = page.waitForResponse(response => response.url().endsWith('/api/runs') && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Start audit', exact: true }).click();
  const first = (await (await firstStarted).json()).run_id as string;
  await expect(page.locator('.stats strong').first()).toHaveText('completed');
  await expect(page.getByLabel('Evidence capture').locator('option')).toHaveCount(1);

  await page.getByLabel(/demo-code/).uncheck();
  await page.getByLabel(/demo-log/).check();
  await page.getByLabel('Investigation').selectOption('crash investigation');
  const secondStarted = page.waitForResponse(response => response.url().endsWith('/api/runs') && response.request().method() === 'POST');
  await page.getByRole('button', { name: 'Start audit', exact: true }).click();
  const second = (await (await secondStarted).json()).run_id as string;
  await expect(page.locator('.stats strong').first()).toHaveText('completed');
  await expect(page.getByLabel('Evidence capture').locator('option')).toHaveCount(1);
  expect(second).not.toBe(first);

  await page.locator('.run-history button').filter({ hasText: 'firmware triage' }).click();
  await expect(page.getByLabel('Evidence capture').locator('option')).toContainText(['0x80000000']);
  const download = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Export JSON', exact: true }).click();
  const report = JSON.parse(await readFile((await (await download).path())!, 'utf8'));
  expect(report.run_id).toBe(first);
  expect(report.acquisitions).toHaveLength(1);
  await page.getByLabel(/Include raw bytes/).check();
  await page.getByRole('button', { name: 'Export evidence bundle' }).click();
  await expect(page.getByTestId('bundle-result')).toContainText('VERIFIED');

  await page.locator('.run-history button').filter({ hasText: 'crash investigation' }).click();
  await expect(page.getByLabel('Evidence capture').locator('option')).toContainText(['0x80001000']);
  await page.getByRole('button', { name: 'Delete run from memory' }).click();
  await page.getByRole('button', { name: 'Delete permanently' }).click();
  await expect(page.locator('.run-history button').filter({ hasText: 'crash investigation' })).toHaveCount(0);
  await expect(page.locator('.run-history button').filter({ hasText: 'firmware triage' })).toHaveCount(1);
  expect((await page.request.get(`/api/runs/${second}`)).status()).toBe(404);
  expect((await page.request.get(`/api/runs/${first}`)).status()).toBe(200);
});

test('failed edge revocation still signs out locally and hides retained evidence', async ({ page }) => {
  await signIn(page);
  const run = await finishedRun(page);
  await page.reload();
  await page.locator('.run-history button').filter({ hasText: run.request.purpose }).first().click();
  await expect(page.getByRole('link', { name: 'Export JSON', exact: true })).toBeVisible();

  await page.route('**/api/logout', async route => {
    const upstream = await route.fetch();
    expect(upstream.status()).toBe(200);
    await route.fulfill({
      response: upstream,
      status: 503,
      contentType: 'application/json',
      body: JSON.stringify({ authenticated: false, edge_sessions_revoked: false }),
    });
  });
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Inspect with evidence.' })).toBeVisible();
  await expect(page.getByRole('alert')).toContainText('Signed out locally. Edge session revocation failed');
  await expect(page.getByRole('link', { name: 'Export JSON', exact: true })).toHaveCount(0);
  expect((await page.request.get('/api/runs')).status()).toBe(401);
});

test('expired operator login returns the console to sign-in', async ({ page }) => {
  await signIn(page);
  expect((await page.request.post('/api/logout')).status()).toBe(200);
  await expect(page.getByRole('heading', { name: 'Inspect with evidence.' })).toBeVisible({ timeout: 10000 });
  await expect(page.getByRole('alert')).toContainText('Operator session expired');
});

test('sign-out handles an already expired operator cookie', async ({ page }) => {
  await signIn(page);
  await page.route('**/api/logout', async route => {
    const upstream = await route.fetch();
    expect(upstream.status()).toBe(200);
    await route.fulfill({ response: upstream, status: 401, body: JSON.stringify({ detail: 'Sign in required' }) });
  });
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Inspect with evidence.' })).toBeVisible();
  await expect(page.getByRole('alert')).toContainText('Operator session expired');
});

test('a delayed readiness response cannot restore the signed-in view after logout', async ({ page }) => {
  await signIn(page);
  let release!: () => void;
  let received!: () => void;
  let delivered!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  const inFlight = new Promise<void>(resolve => { received = resolve; });
  const completed = new Promise<void>(resolve => { delivered = resolve; });
  await page.route('**/api/config', async route => {
    const upstream = await route.fetch();
    received();
    await held;
    await route.fulfill({ response: upstream });
    delivered();
  });
  await inFlight;
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Inspect with evidence.' })).toBeVisible();
  release();
  await completed;
  await expect(page.getByRole('button', { name: 'Start audit', exact: true })).toHaveCount(0);
});
