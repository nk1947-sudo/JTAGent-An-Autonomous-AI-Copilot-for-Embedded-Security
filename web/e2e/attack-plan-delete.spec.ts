import { test, expect, signIn } from './fixtures';

async function seedTerminalPlan(page: Parameters<typeof signIn>[0]) {
  const config = await (await page.request.get('/api/config')).json();
  const created = await page.request.post('/api/attack-lab/plans', {
    data: {
      target_id: config.profile.target_id,
      module_id: 'jtag-debug-lock-audit',
      objective: 'Review mock JTAG exposure',
      authorization_acknowledged: true,
    },
  });
  expect(created.status(), await created.text()).toBe(200);
  const id = (await created.json()).plan_id as string;
  const aborted = await page.request.post(`/api/attack-lab/plans/${id}/abort`);
  expect(aborted.status(), await aborted.text()).toBe(200);
  return id;
}

test('saved plans survive reload and can be deleted while exports remain available', async ({ page }) => {
  await signIn(page);
  const id = await seedTerminalPlan(page);
  const otherId = await seedTerminalPlan(page);
  const exported = await page.request.post(`/api/attack-lab/plans/${id}/bundle`, {
    data: { include_raw: false },
  });
  expect(exported.status(), await exported.text()).toBe(200);
  const bundleId = ((await exported.json()).path as string).split(/[\\/]/).pop()!;

  await page.reload();
  await page.getByRole('button', { name: 'Attack Lab', exact: true }).click();
  const saved = page.getByLabel('Saved Attack Lab plans');
  await expect(saved.locator(`option[value="${id}"]`)).toHaveCount(1);
  await saved.selectOption(id);
  await page.getByRole('button', { name: 'Export evidence bundle' }).click();
  await expect(page.getByTestId('bundle-result')).toBeVisible();
  await saved.selectOption(otherId);
  await expect(page.getByTestId('bundle-result')).toHaveCount(0);
  await saved.selectOption(id);
  await expect(page.getByRole('button', { name: 'Delete plan from memory' })).toBeEnabled();
  await page.getByRole('button', { name: 'Delete plan from memory' }).click();
  await expect(page.getByRole('heading', { name: 'Delete in-memory plan?' })).toBeVisible();
  await page.getByRole('button', { name: 'Keep plan' }).click();
  await expect(saved).toHaveValue(id);

  await page.getByRole('button', { name: 'Delete plan from memory' }).click();
  await page.getByRole('button', { name: 'Delete plan', exact: true }).click();
  await expect(saved).toHaveValue('');
  await expect(saved.locator(`option[value="${id}"]`)).toHaveCount(0);
  await expect(page.getByRole('status').filter({ hasText: 'Plan deleted from memory' })).toBeVisible();
  expect((await page.request.get(`/api/exports/${bundleId}/manifest.json`)).status()).toBe(200);
});

test('pending deletion keeps the plan selected and API failures are visible', async ({ page }) => {
  await signIn(page);
  const id = await seedTerminalPlan(page);
  await page.getByRole('button', { name: 'Attack Lab', exact: true }).click();
  const saved = page.getByLabel('Saved Attack Lab plans');
  await saved.selectOption(id);
  const url = `**/api/attack-lab/plans/${id}`;
  let release!: () => void;
  let requested!: () => void;
  const pending = new Promise<void>(resolve => { requested = resolve; });
  await page.route(url, async route => {
    if (route.request().method() !== 'DELETE') return route.continue();
    await new Promise<void>(resolve => { release = resolve; requested(); });
    await route.fulfill({ status: 409, json: { detail: 'Complete or abort the plan before deletion' } });
  });
  await page.getByRole('button', { name: 'Delete plan from memory' }).click();
  await page.getByRole('button', { name: 'Delete plan', exact: true }).click();
  await pending;
  await expect(page.getByRole('status').filter({ hasText: 'Deleting plan from memory' })).toBeVisible();
  await expect(saved).toHaveValue(id);
  release();
  await expect(page.getByRole('alert')).toContainText('Complete or abort the plan before deletion');
  await expect(saved).toHaveValue(id);
  await page.unroute(url);

  await page.route(url, async route => {
    if (route.request().method() !== 'DELETE') return route.continue();
    await route.fulfill({ status: 404, json: { detail: 'Attack plan not found' } });
  });
  await page.getByRole('button', { name: 'Delete plan from memory' }).click();
  await page.getByRole('button', { name: 'Delete plan', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Attack plan not found');
  await expect(saved).toHaveValue(id);
  await page.unroute(url);
  expect((await page.request.delete(`/api/attack-lab/plans/${id}`)).status()).toBe(200);
});
