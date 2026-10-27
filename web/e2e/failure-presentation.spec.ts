import { test, expect, signIn, finishedRun } from './fixtures';

test('full run capacity is shown without starting another audit', async ({ page }) => {
  await signIn(page);
  await page.route('**/api/runs', route => route.request().method() === 'POST'
    ? route.fulfill({ status: 429, json: { detail: 'Delete old runs to free in-memory capacity' } })
    : route.continue());
  await page.getByRole('button', { name: 'Start audit', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Delete old runs to free in-memory capacity');
  await expect(page.locator('.stats strong').first()).toHaveText('Ready');
});

test('cancelled and model-failure records have distinct operator guidance', async ({ page }) => {
  await signIn(page);
  const run = await finishedRun(page);
  await page.reload();
  let reason = 'operator_cancelled';
  await page.route(`**/api/runs/${run.run_id}`, route => route.request().method() === 'GET'
    ? route.fulfill({ json: { ...run, status: reason === 'operator_cancelled' ? 'cancelled' : 'failed',
      termination_reason: reason, errors: reason === 'operator_cancelled' ? [] : ['InferenceError'] } })
    : route.continue());
  const history = page.locator('.run-history button').filter({ hasText: run.request.purpose }).first();
  await history.click();
  await expect(page.locator('.failure-help')).toContainText('The operator cancelled this run; collected evidence remains available.');
  reason = 'dependency_failure';
  await history.click();
  await expect(page.locator('.failure-help')).toContainText('A local target or inference dependency failed.');
  await expect(page.getByRole('button', { name: 'Retry audit' })).toBeVisible();
});

test('a fabricated evidence citation is retained as rejected, not shown as an accepted finding', async ({ page }) => {
  await signIn(page);
  const run = await finishedRun(page);
  expect(run.findings.length).toBeGreaterThan(0);
  await page.reload();
  await page.route(`**/api/runs/${run.run_id}`, route => route.request().method() === 'GET'
    ? route.fulfill({ json: { ...run, findings: [{ ...run.findings[0], status: 'rejected', evidence_ids: ['fabricated-evidence'] }] } })
    : route.continue());
  await page.locator('.run-history button').filter({ hasText: run.request.purpose }).first().click();
  await expect(page.getByRole('heading', { name: 'Rejected by evidence verifier' })).toBeVisible();
  await expect(page.locator('.finding:not(.rejected)')).toHaveCount(0);
});
