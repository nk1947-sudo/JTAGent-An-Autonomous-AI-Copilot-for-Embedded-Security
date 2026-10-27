import { test, expect, signIn } from './fixtures';

test('the last history selection wins when an earlier response arrives late', async ({ page }) => {
  await signIn(page);
  const profile = (await (await page.request.get('/api/config')).json()).profile;
  const create = async (purpose: string) => {
    const response = await page.request.post('/api/runs', {
      data: { target_id: profile.target_id, purpose, region_names: ['demo-code'], byte_budget: 256 },
    });
    expect(response.status()).toBe(200);
    const id = (await response.json()).run_id as string;
    await expect.poll(async () => (await (await page.request.get(`/api/runs/${id}`)).json()).status).toBe('completed');
    return id;
  };
  const firstId = await create('firmware triage');
  await create('crash investigation');
  await page.reload();
  const first = page.locator('.run-history button').filter({ hasText: 'firmware triage' }).first();
  const second = page.locator('.run-history button').filter({ hasText: 'crash investigation' }).first();
  await expect(first).toBeVisible();
  await expect(second).toBeVisible();

  let release!: () => void;
  let received!: () => void;
  let delivered!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  const inFlight = new Promise<void>(resolve => { received = resolve; });
  const completed = new Promise<void>(resolve => { delivered = resolve; });
  await page.route(`**/api/runs/${firstId}`, async route => {
    const response = await route.fetch();
    received();
    await held;
    await route.fulfill({ response });
    delivered();
  });
  await first.click();
  await inFlight;
  await second.click();
  await expect(second).toHaveClass(/selected/);
  release();
  await completed;
  await page.waitForTimeout(250);
  await expect(second).toHaveClass(/selected/);
});
