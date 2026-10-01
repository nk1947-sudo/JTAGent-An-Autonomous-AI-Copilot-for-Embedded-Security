import { spawnSync } from 'node:child_process';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, expect } from './fixtures';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const verify = (bundle: string) =>
  spawnSync('uv', ['run', '--project', root, 'python', 'scripts/verify_bundle.py', bundle], { cwd: root, encoding: 'utf8' });

test('isolated mock stack: audit, evidence, exports, verified bundle, Attack Lab and Workbench', async ({ page, stack }) => {
  // The stack is the test's own, not the live one.
  const ports = [stack.orchestrator, stack.edge].map(u => new URL(u).port);
  expect(ports).not.toContain('8000');
  expect(ports).not.toContain('8001');
  expect(stack.modes).toEqual({ target: 'mock', inference: 'scripted' });

  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.goto('/');
  await page.getByLabel('Operator password').fill(stack.password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByText('MOCK TARGET', { exact: true })).toBeVisible();
  await expect(page.getByText('SCRIPTED ANALYSIS', { exact: true })).toBeVisible();
  await expect(page.getByText('Edge API', { exact: true })).toBeVisible();
  await expect(page.getByTestId('readiness-verdict')).toHaveText('READY · NON-LIVE BACKEND');
  await page.getByRole('button', { name: 'Start audit', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Captured printable string' }).first()).toBeVisible({ timeout: 15000 });
  await expect(page.getByText('Checked references, addresses and claim status', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: /Evidence / }).first().click();
  await expect(page.getByText('Raw bytes withheld by edge data policy', { exact: true })).toBeVisible();

  const download = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Export JSON', exact: true }).click();
  const data = JSON.parse(await readFile((await (await download).path())!, 'utf8'));
  expect(data.target_backend).toBe('mock');
  expect(data.inference_backend).toBe('scripted');
  expect(data.captures.length).toBe(2);
  expect(data.acquisitions.length).toBe(2);
  expect(data.findings.every((f: { status: string }) => f.status === 'observed')).toBeTruthy();
  expect(JSON.stringify(data)).not.toContain('synthetic-secret');
  expect(errors).toEqual([]);

  // Local evidence bundle with raw bytes, then offline verification and tamper detection.
  await page.getByLabel(/Include raw bytes/).check();
  await page.getByRole('button', { name: 'Export evidence bundle' }).click();
  const result = page.getByTestId('bundle-result');
  await expect(result).toContainText('VERIFIED');
  await expect(result).toContainText('2/2 captures with raw bytes');
  const bundle = (await result.locator('code').first().textContent())!;
  expect(bundle.startsWith(stack.export_dir)).toBeTruthy();
  const ok = verify(bundle);
  expect(ok.status, ok.stdout + ok.stderr).toBe(0);
  expect(ok.stdout).toContain('VERIFIED');
  const raw = path.join(bundle, 'captures', (await readdir(path.join(bundle, 'captures')))[0]);
  const bytes = await readFile(raw);
  bytes[0] ^= 0xff;
  await writeFile(raw, bytes);
  expect(verify(bundle).status).toBe(1);

  await page.getByRole('button', { name: 'Attack Lab', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Attack Lab', exact: true })).toBeVisible();
  await page.getByLabel('Security research instruction').fill('Assess JTAG debug lock and halt exposure');
  await page.getByRole('button', { name: 'Get model recommendations' }).click();
  await expect(page.getByRole('heading', { name: 'JTAG exposure and debug-lock audit', level: 2 })).toBeVisible();
  await page.getByRole('checkbox').check();
  await page.getByRole('button', { name: 'Create HITL plan' }).click();
  await expect(page.getByText('pending approval', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Execute next approved step' }).click();
  await page.getByRole('button', { name: 'Execute next approved step' }).click();
  await page.getByRole('button', { name: 'Approve step' }).click();
  await page.getByRole('button', { name: 'Execute next approved step' }).click();
  await expect(page.getByText(/Real JTAG execution is disabled/)).toBeVisible();
  await expect(page.getByText('NO PHYSICAL ATTACK PERFORMED', { exact: true })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Export Markdown' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Export JSON' })).toBeVisible();
  await page.getByRole('button', { name: 'AI Workbench', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'AI Firmware Workbench', exact: true })).toBeVisible();
  await expect(page.getByText('LIVE WRITES DISABLED', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Investigation', exact: true }).click();

  await page.getByRole('button', { name: 'Delete run from memory' }).click();
  await expect(page.getByRole('heading', { name: 'Delete in-memory evidence?' })).toBeVisible();
  await page.getByRole('button', { name: 'Delete permanently' }).click();
  await expect(page.getByText('No evidence collected. Start an audit to inspect approved memory.')).toBeVisible();
  // The durable bundle outlives the deleted in-memory run.
  const exports = await (await page.request.get('/api/exports')).json();
  expect(exports.some((b: { bundle_id: string }) => bundle.endsWith(b.bundle_id))).toBeTruthy();
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Inspect with evidence.' })).toBeVisible();
  expect(errors).toEqual([]);
});

test('the stack cannot reach hardware even though this shell may be configured for it', async ({ page, stack }) => {
  await page.goto('/');
  await page.getByLabel('Operator password').fill(stack.password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  const config = await (await page.request.get('/api/config')).json();
  expect(config.target.target_backend).toBe('mock');
  expect(config.inference_backend).toBe('scripted');
  expect(config.uart.enabled).toBe(false);
  expect(config.attack_lab.live_jtag_enabled).toBe(false);
  expect(config.readiness.debugger.applicable).toBe(false);
  expect(config.readiness.live_ready).toBe(false);
});
