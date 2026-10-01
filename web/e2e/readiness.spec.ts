import { test, expect, signIn } from './fixtures';

test('current edge: every status layer is shown separately with the loaded build identity', async ({ page, stack }) => {
  await signIn(page);
  await expect(page.getByTestId('layer-application')).toContainText('ok');
  await expect(page.getByTestId('layer-debugger-reachable')).toContainText('unknown'); // mock: no debugger
  await expect(page.getByTestId('layer-openocd-version')).toContainText('not applicable');
  await expect(page.getByTestId('layer-target-communication')).toContainText('ok');
  await expect(page.getByTestId('layer-execution-state')).toContainText('running');
  await expect(page.getByTestId('layer-snapshots-armed')).toContainText('yes');
  await expect(page.getByTestId('layer-recovery-required')).toContainText('no');
  await expect(page.getByTestId('layer-status-schema')).toContainText('v2');
  // The build shown is what the processes report about themselves, not a recomputation.
  const edge = (await (await page.request.get(stack.edge + '/healthz')).json()).build;
  const orchestrator = (await (await page.request.get('/healthz')).json()).build;
  expect(edge.component).toBe('edge');
  expect(orchestrator.component).toBe('orchestrator');
  await expect(page.getByTestId('readiness-panel')).toContainText(edge.build_id);
  await expect(page.getByTestId('readiness-panel')).toContainText(orchestrator.build_id);
  await expect(page.getByRole('button', { name: 'Start audit', exact: true })).toBeEnabled();
});

test('an old flat-schema edge is shown as incompatible and live controls are disabled and refused', async ({ page, stack }) => {
  await page.goto(stack.legacy_orchestrator + '/');
  await page.getByLabel('Operator password').fill(stack.password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByTestId('readiness-verdict')).toHaveText('INCOMPATIBLE EDGE');
  await expect(page.getByTestId('readiness-blockers')).toContainText('legacy_flat_schema');
  await expect(page.getByTestId('layer-status-schema')).toContainText('none / unsupported');
  await expect(page.getByRole('button', { name: 'Start audit', exact: true })).toBeDisabled();
  await expect(page.getByTestId('start-blocked')).toContainText('legacy_flat_schema');
  // A disabled button is not the policy boundary: the server refuses the same request.
  const config = await (await page.request.get(stack.legacy_orchestrator + '/api/config')).json();
  const refused = await page.request.post(stack.legacy_orchestrator + '/api/runs', {
    data: { target_id: config.profile.target_id, purpose: 'bootloader inspection', region_names: ['demo-code'] },
  });
  expect(refused.status()).toBe(409);
  expect((await refused.json()).detail).toContain('legacy_flat_schema');
  // Retained-evidence review and offline tools stay usable.
  await page.getByRole('button', { name: 'AI Workbench', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'AI Firmware Workbench', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Attack Lab', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Attack Lab', exact: true })).toBeVisible();
});

test('an orchestrator without the readiness contract is treated as blocked, never as ready', async ({ page, stack }) => {
  await page.route('**/api/config', async route => {
    const body = await (await route.fetch()).json();
    delete body.readiness; // what a pre-contract orchestrator would send
    await route.fulfill({ json: body });
  });
  await page.goto('/');
  await page.getByLabel('Operator password').fill(stack.password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByTestId('readiness-verdict')).toHaveText('INCOMPATIBLE EDGE');
  await expect(page.getByTestId('readiness-blockers')).toContainText('orchestrator_legacy_config');
  await expect(page.getByRole('button', { name: 'Start audit', exact: true })).toBeDisabled();
});

test('recovery-required and an unreachable edge are represented accurately', async ({ page }) => {
  let mode: 'recovery' | 'offline' = 'recovery';
  await page.route('**/api/config', async route => {
    const response = await route.fetch();
    if (!response.ok()) return route.fulfill({ response }); // e.g. 401 before sign-in
    const body = await response.json();
    if (mode === 'recovery') {
      Object.assign(body.readiness, { run_ready: false, live_ready: false, recovery_required: true,
        blockers: [{ code: 'recovery_required', message: 'A previous operation left the target uncertain.' }] });
    } else if (mode === 'offline') {
      body.profile = null;
      Object.assign(body.readiness, { edge: 'unreachable', compatible: false, run_ready: false, live_ready: false,
        target_backend: null, debugger: null, target: null, snapshots_armed: null, recovery_required: null, edge_build: null,
        blockers: [{ code: 'edge_unreachable', message: 'The edge service could not be reached.' }] });
    }
    await route.fulfill({ json: body });
  });
  await signIn(page);
  await expect(page.getByTestId('readiness-verdict')).toHaveText('BLOCKED');
  await expect(page.getByTestId('layer-recovery-required')).toContainText('YES');
  await expect(page.getByTestId('readiness-blockers')).toContainText('recovery_required');
  await expect(page.getByRole('button', { name: 'Start audit', exact: true })).toBeDisabled();

  mode = 'offline';
  await page.reload(); // the session cookie persists; only the edge is 'down'
  await expect(page.getByTestId('edge-offline')).toBeVisible();
  await expect(page.getByTestId('readiness-verdict').first()).toHaveText('EDGE UNREACHABLE');
  await expect(page.getByTestId('layer-execution-state').first()).toContainText('unknown'); // never assumed
  await expect(page.getByRole('button', { name: 'Start audit', exact: true })).toHaveCount(0);
});

test('status that stops refreshing is marked stale and blocks the start control', async ({ page }) => {
  await page.clock.install();
  await signIn(page);
  await expect(page.getByTestId('readiness-verdict')).toHaveText('READY · NON-LIVE BACKEND');
  await page.route('**/api/config', route => route.abort());
  await page.clock.fastForward(30_000); // more than the freshness limit with every refresh failing
  await expect(page.getByTestId('readiness-verdict')).toHaveText('STATUS STALE');
  await expect(page.getByRole('button', { name: 'Start audit', exact: true })).toBeDisabled();
  await expect(page.getByTestId('start-blocked')).toContainText('stale');
});
