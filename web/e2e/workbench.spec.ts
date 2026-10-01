import type { Page } from '@playwright/test';
import { test, expect, signIn, finishedRun } from './fixtures';

const advice = (actions: unknown[], extra: object = {}) => ({
  summary: 'Vector table observed', hypothesis: 'Hypothesis, not a finding.', observations: ['PC read from registers'],
  actions, limitations: ['No symbols'], ...extra,
});
const action = (operation: string, extra: object = {}) => ({ operation, rationale: 'because', address: null, length: null, count: null, requires_approval: true, ...extra });

/**
 * Backend-generated evidence: a real Attack Lab plan (created through the API) whose capture and
 * register data come from a real mock audit, returned by the plan list the Workbench reads.
 */
async function openWorkbenchWithEvidence(page: Page) {
  const run = await finishedRun(page);
  const config = await (await page.request.get('/api/config')).json();
  const plan = await (await page.request.post('/api/attack-lab/plans', {
    data: { target_id: config.profile.target_id, module_id: 'jtag-debug-lock-audit', objective: 'Assess JTAG exposure', authorization_acknowledged: true },
  })).json();
  const withEvidence = { ...plan, captures: run.captures, registers: run.registers, acquisitions: run.acquisitions, evidence_ids: run.captures.map((c: { evidence_id: string }) => c.evidence_id) };
  await page.route('**/api/attack-lab/plans', route => route.request().method() === 'GET' ? route.fulfill({ json: [withEvidence] }) : route.continue());
  await page.getByRole('button', { name: 'AI Workbench', exact: true }).click();
  await expect(page.getByText('EVIDENCE LINKED')).toBeVisible();
  return withEvidence;
}
const ask = (page: Page) => page.getByRole('button', { name: 'Ask debugger agent' }).click();

test.beforeEach(async ({ page }) => { await signIn(page); });

test('addressless and zero-valued actions render; null fields show nothing meaningless', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await openWorkbenchWithEvidence(page);
  await page.route('**/api/debugger/advice', route => route.fulfill({ json: advice([
    action('inspect_registers'),                                  // address, length, count all null
    action('disassemble', { address: 0, length: 4 }),             // a valid zero address must be kept
    action('capture_memory', { address: 1076823040, length: 16, count: 2, requires_approval: false }),
  ]) }));
  await ask(page);
  const items = page.getByTestId('advice-action');
  await expect(items).toHaveCount(3);
  await expect(items.nth(0)).toContainText('inspect registers');
  await expect(items.nth(0).locator('code')).toHaveCount(0);      // nothing to show for a null address
  await expect(items.nth(0)).not.toContainText('null');
  await expect(items.nth(1).locator('code')).toHaveText('0x00000000 · 4 bytes');
  await expect(items.nth(2).locator('code')).toHaveText('0x402f0400 · 16 bytes · × 2');
  await expect(items.nth(2)).toContainText('read-only');
  expect(errors).toEqual([]);
});

test('malformed advice shows a controlled error and keeps the evidence view', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await openWorkbenchWithEvidence(page);
  for (const bad of [
    { ...advice([]), actions: 'not-a-list' },
    advice([action('disassemble', { address: '0x10' })]),         // string where an integer is required
    advice([action('disassemble', { length: 99999 })]),           // outside the contract's bounds
    { summary: 'x' },                                             // required fields missing
  ]) {
    await page.route('**/api/debugger/advice', route => route.fulfill({ json: bad }));
    await ask(page);
    await expect(page.getByTestId('advice-error')).toContainText('did not match the backend contract');
    await expect(page.getByTestId('advice')).toHaveCount(0);
    await expect(page.getByRole('heading', { name: 'Memory and disassembly' })).toBeVisible();
    await expect(page.locator('.capture-meta')).toBeVisible();   // valid evidence stays on screen
    await page.getByTestId('advice-error').getByRole('button', { name: 'Dismiss' }).click();
    await page.unroute('**/api/debugger/advice');
  }
  expect(errors).toEqual([]);
});

test('a backend failure is inline and recoverable; unknown action types are flagged not trusted', async ({ page }) => {
  await openWorkbenchWithEvidence(page);
  let fail = true;
  await page.route('**/api/debugger/advice', route => fail
    ? route.fulfill({ status: 503, json: { detail: 'Debugger agent unavailable; no fallback' } })
    : route.fulfill({ json: advice([action('teleport_cpu', { address: 4 }), action('inspect_registers')]) }));
  await ask(page);
  await expect(page.getByTestId('advice-error')).toContainText('Debugger agent unavailable; no fallback');
  await expect(page.getByRole('heading', { name: 'Memory and disassembly' })).toBeVisible();
  fail = false;
  await ask(page);
  await expect(page.getByTestId('advice-error')).toHaveCount(0);
  const items = page.getByTestId('advice-action');
  await expect(items).toHaveCount(2);
  await expect(items.nth(0)).toContainText('UNRECOGNIZED · not executable');
  await expect(items.nth(1)).toContainText('HITL required');
});

test('a rendering failure in Workbench is contained; the rest of the application keeps working', async ({ page }) => {
  await openWorkbenchWithEvidence(page);
  await page.route('**/api/debugger/advice', route => route.fulfill({ json: advice([action('inspect_registers')]) }));
  // Simulate an unforeseen render-time exception inside the advice view only.
  await page.evaluate(() => {
    const original = String.prototype.replaceAll;
    (window as unknown as { __restore: () => void }).__restore = () => { String.prototype.replaceAll = original; };
    String.prototype.replaceAll = function (this: string, ...args: [string, string]) {
      if (String(this) === 'inspect_registers') throw new Error('injected render failure');
      return original.apply(this, args as never);
    } as typeof original;
  });
  await ask(page);
  const boundary = page.getByTestId('error-boundary');
  await expect(boundary).toContainText('Debugger guidance could not be displayed');
  await expect(page.getByRole('heading', { name: 'AI Firmware Workbench', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Memory and disassembly' })).toBeVisible();
  await expect(page.locator('.capture-meta')).toBeVisible();
  await page.getByRole('button', { name: 'Investigation', exact: true }).click(); // other areas still work
  await expect(page.getByRole('button', { name: 'Start audit', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: 'AI Workbench', exact: true }).click();
  await page.evaluate(() => (window as unknown as { __restore: () => void }).__restore());
  // Recovery: with the fault gone, the same request renders normally after the page is re-entered.
  await page.getByRole('button', { name: 'Ask debugger agent' }).click();
  await expect(page.getByTestId('advice-action')).toHaveCount(1);
  await expect(page.getByTestId('error-boundary')).toHaveCount(0);
});

test('a retained plan that violates the contract is hidden with an explanation', async ({ page }) => {
  await openWorkbenchWithEvidence(page);
  const run = await finishedRun(page);
  await page.route('**/api/attack-lab/plans', route => route.request().method() === 'GET'
    ? route.fulfill({ json: [{ plan_id: 'x', captures: run.captures, module_id: 42 }] }) : route.continue());
  await page.getByRole('button', { name: 'Investigation', exact: true }).click();
  await page.getByRole('button', { name: 'AI Workbench', exact: true }).click();
  await expect(page.getByRole('alert').first()).toContainText('failed contract validation');
  await expect(page.getByText('NO CAPTURE')).toBeVisible();
});
