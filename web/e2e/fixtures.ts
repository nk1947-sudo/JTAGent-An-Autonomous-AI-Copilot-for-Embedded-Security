import { test as base, expect, type Page } from '@playwright/test';

export type Stack = {
  orchestrator: string; edge: string; legacy_orchestrator: string; legacy_edge: string;
  password: string; export_dir: string; log_dir: string;
  modes: { target: string; inference: string }; pids: number[];
};

export const currentStack = (): Stack => JSON.parse(process.env.E2E_STACK!);

export const test = base.extend<{ stack: Stack }>({
  stack: async ({}, use) => { await use(currentStack()); },
  baseURL: async ({ stack }, use) => { await use(stack.orchestrator); },
});
export { expect };

export async function signIn(page: Page, password = currentStack().password) {
  await page.goto('/');
  await page.getByLabel('Operator password').fill(password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByTestId('readiness-panel')).toBeVisible();
}

/** Real, backend-generated evidence: run a mock audit through the API and wait for it to finish. */
export async function finishedRun(page: Page) {
  const config = await (await page.request.get('/api/config')).json();
  const started = await page.request.post('/api/runs', {
    data: { target_id: config.profile.target_id, purpose: 'bootloader inspection', region_names: config.profile.regions.filter((r: { approved: boolean }) => r.approved).map((r: { name: string }) => r.name) },
  });
  expect(started.ok()).toBeTruthy();
  const { run_id } = await started.json();
  for (let i = 0; i < 100; i++) {
    const run = await (await page.request.get('/api/runs/' + run_id)).json();
    if (!['queued', 'running'].includes(run.status)) return run;
    await page.waitForTimeout(100);
  }
  throw new Error('run did not finish');
}
