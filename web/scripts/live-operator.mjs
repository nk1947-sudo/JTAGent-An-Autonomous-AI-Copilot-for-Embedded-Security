import { chromium } from 'playwright';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { safeScreenshot } from './safe-screenshot.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const output = path.join(root, 'tmp', 'acceptance-live');
const password = process.env.JTAGENT_DASHBOARD_PASSWORD;
if (!password) throw new Error('JTAGENT_DASHBOARD_PASSWORD is required');
const action = process.argv[2];
if (!['inspect', 'inventory', 'audit', 'inspect-run', 'attack-plan', 'workbench-accept', 'auth-cycle', 'uart-passive'].includes(action)) throw new Error('Unknown live operator action');
await mkdir(output, { recursive: true });

const errors = [];
let signedIn = false;
const redact = text => String(text).replaceAll(password, '[redacted]').replace(/(Bearer|password|token|cookie)\s*[:=]\s*[^\s,;]+/gi, '$1=[redacted]');
const safePath = url => { try { return new URL(url).pathname; } catch { return '[invalid URL]'; } };
const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true });
  const page = await context.newPage();
  const record = event => errors.push({ phase: signedIn ? 'authenticated' : 'pre_auth', ...event });
  page.on('pageerror', error => record({ type: 'pageerror', detail: redact(error.message) }));
  page.on('console', message => { if (message.type() === 'error') record({ type: 'console', detail: redact(message.text()) }); });
  page.on('requestfailed', request => record({ type: 'requestfailed', path: safePath(request.url()), detail: redact(request.failure()?.errorText || '') }));
  page.on('response', response => { if (response.status() >= 400) record({ type: 'http', path: safePath(response.url()), status: response.status() }); });

  await page.goto('http://127.0.0.1:8000/', { waitUntil: 'domcontentloaded' });
  await page.getByLabel('Operator password').fill(password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.getByTestId('readiness-verdict').waitFor({ timeout: 15000 });
  signedIn = true;
  const verdict = (await page.getByTestId('readiness-verdict').innerText()).trim();
  const mode = (await page.locator('.modebox').innerText()).trim();
  const profile = (await page.getByLabel('Target profile').inputValue()).trim();
  const regions = await page.locator('.region').allInnerTexts();
  const memoryMap = (await page.locator('.memory-map').innerText()).trim();
  const history = (await page.locator('.run-history').innerText()).trim();
  const layers = await page.locator('[data-testid^="layer-"]').allInnerTexts();
  if (profile !== 'beaglebone-black-am335x' || !mode.includes('OPENOCD TARGET') || !mode.includes('SCRIPTED ANALYSIS') || !verdict.includes('LIVE OPERATIONS READY') || regions.length !== 1 || !memoryMap.includes('64 bytes')) {
    throw new Error('Rendered live target, inference, readiness, or 64-byte scope did not match the approved session');
  }
  if (action === 'inspect') {
    await safeScreenshot(page, path.join(output, 'live-readiness.png'));
    await page.getByRole('button', { name: 'Attack Lab', exact: true }).click();
    await page.getByRole('heading', { name: 'Attack Lab', exact: true }).waitFor();
    await safeScreenshot(page, path.join(output, 'live-attack-lab.png'));
    await page.getByRole('button', { name: 'AI Workbench', exact: true }).click();
    await page.getByRole('heading', { name: 'AI Firmware Workbench', exact: true }).waitFor();
    await safeScreenshot(page, path.join(output, 'live-workbench.png'));
    const summary = { verdict, profile, mode, regions, memoryMap, history, layers, screenshots: ['live-readiness.png', 'live-attack-lab.png', 'live-workbench.png'] };
    await writeFile(path.join(output, 'read-only-summary.json'), JSON.stringify(summary, null, 2), 'utf8');
    console.log(JSON.stringify({ ...summary, mode: mode.split('\n').filter(line => line.includes('TARGET') || line.includes('ANALYSIS')) }));
  }
  if (action === 'inventory') {
    const [runResponse, planResponse, exportResponse] = await Promise.all([
      page.request.get('http://127.0.0.1:8000/api/runs'),
      page.request.get('http://127.0.0.1:8000/api/attack-lab/plans'),
      page.request.get('http://127.0.0.1:8000/api/exports'),
    ]);
    if (![runResponse, planResponse, exportResponse].every(response => response.ok())) throw new Error('Authenticated inventory request failed');
    const runs = await runResponse.json(), plans = await planResponse.json(), exports = await exportResponse.json();
    const planIds = plans.map(item => item.plan_id);
    if (await page.locator('.run-history button').count() !== runs.length) throw new Error('Rendered run history disagrees with the authenticated inventory');
    await safeScreenshot(page, path.join(output, 'live-inventory-investigation.png'));
    await page.getByRole('button', { name: 'Attack Lab', exact: true }).click();
    const planSelect = page.getByLabel('Saved Attack Lab plans');
    for (const plan of plans) {
      await planSelect.selectOption(plan.plan_id);
      const reportJson = page.getByRole('link', { name: 'Export JSON', exact: true });
      const reportMarkdown = page.getByRole('link', { name: 'Export Markdown', exact: true });
      if (!(await reportJson.getAttribute('href'))?.endsWith(`/api/attack-lab/plans/${plan.plan_id}/report.json`) || !(await reportMarkdown.getAttribute('href'))?.endsWith(`/api/attack-lab/plans/${plan.plan_id}/report.md`) || await page.getByRole('button', { name: 'Export evidence bundle' }).count() !== 1) throw new Error('Rendered plan report or bundle control is unavailable');
    }
    await safeScreenshot(page, path.join(output, 'live-inventory-attack-lab.png'));
    await page.getByRole('button', { name: 'AI Workbench', exact: true }).click();
    const workbenchSelect = page.getByLabel('JTAG evidence plan');
    for (const plan of plans) {
      await workbenchSelect.selectOption(plan.plan_id);
      await page.getByText(plan.captures?.length ? 'EVIDENCE LINKED' : 'NO CAPTURE', { exact: true }).waitFor();
    }
    await safeScreenshot(page, path.join(output, 'live-inventory-workbench.png'));
    const exportedSubjects = exports.map(item => `${item.subject_kind}:${item.subject_id}`);
    const summary = { verdict, runs: runs.map(item => ({ run_id: item.run_id, status: item.status, capture_count: item.capture_count, exported: exportedSubjects.includes(`run:${item.run_id}`) })), plans: plans.map(item => ({ plan_id: item.plan_id, source_run_id: item.source_run_id, status: item.status, capture_count: item.captures?.length, exported: exportedSubjects.includes(`attack_plan:${item.plan_id}`) })), exports: exports.map(item => ({ bundle_id: item.bundle_id, subject_kind: item.subject_kind, subject_id: item.subject_id, verification: item.verification, raw_included: item.raw_included })), rendered_run_count: runs.length, rendered_plan_ids: planIds, screenshots: ['live-inventory-investigation.png', 'live-inventory-attack-lab.png', 'live-inventory-workbench.png'] };
    await writeFile(path.join(output, 'live-inventory-summary.json'), JSON.stringify(summary, null, 2), 'utf8');
    console.log(JSON.stringify(summary));
  }
  if (action === 'audit') {
    const selected = page.locator('.region input[type="checkbox"]');
    if (await selected.count() !== 1 || !await selected.first().isChecked()) throw new Error('Exactly one approved 64-byte region must be selected');
    await page.getByLabel('Investigation').selectOption({ label: 'bootloader inspection' });
    await page.getByLabel('Memory budget').selectOption('256');
    if (await page.getByLabel('Memory budget').inputValue() !== '256') throw new Error('Minimum configured UI budget was not selected');
    const [createdResponse] = await Promise.all([
      page.waitForResponse(response => safePath(response.url()) === '/api/runs' && response.request().method() === 'POST', { timeout: 15000 }),
      page.getByRole('button', { name: 'Start audit', exact: true }).click(),
    ]);
    if (createdResponse.status() !== 200) throw new Error(`Audit creation returned HTTP ${createdResponse.status()}`);
    const created = await createdResponse.json();
    if (!created.run_id) throw new Error('Audit creation omitted its run ID');
    await safeScreenshot(page, path.join(output, 'live-audit-started.png'));
    await page.waitForFunction(() => {
      const state = document.querySelector('.stats > div:first-child strong')?.textContent?.trim();
      return state && !['Ready', 'queued', 'running'].includes(state);
    }, null, { timeout: 135000 });
    const response = await page.request.get(`http://127.0.0.1:8000/api/runs/${created.run_id}`);
    if (!response.ok()) throw new Error(`Run lookup returned HTTP ${response.status()}`);
    const run = await response.json();
    const readinessResponse = await page.request.get('http://127.0.0.1:8000/api/readiness');
    if (!readinessResponse.ok()) throw new Error(`Final readiness returned HTTP ${readinessResponse.status()}`);
    const finalReadiness = await readinessResponse.json();
    const summary = {
      run_id: created.run_id,
      purpose: run.purpose,
      status: run.status,
      termination_reason: run.termination_reason,
      target_backend: run.target_backend,
      inference_backend: run.inference_backend,
      model_id: run.model_id,
      bytes_requested: run.bytes_requested,
      capture_count: run.captures?.length,
      captures: (run.captures || []).map(c => ({ evidence_id: c.evidence_id, base_address: c.base_address, requested_length: c.requested_length, returned_length: c.returned_length, source_mode: c.source_mode, address_space: c.address_space, target_state: c.target_state, generation: c.generation, content_hash: c.content_hash })),
      acquisitions: (run.acquisitions || []).map(a => ({ initial_state: a.initial_state, final_state: a.final_state, restoration: a.restoration, outcome_uncertain: a.outcome_uncertain, error: a.error })),
      finding_count: run.findings?.length,
      errors: run.errors,
      timeline: await page.locator('.timeline .event').allInnerTexts(),
      final_target_state: finalReadiness.target?.execution_state,
      final_recovery_required: finalReadiness.recovery_required,
      final_live_ready: finalReadiness.live_ready,
    };
    await safeScreenshot(page, path.join(output, 'live-audit-final.png'));
    await writeFile(path.join(output, 'audit-summary.json'), JSON.stringify(summary, null, 2), 'utf8');
    console.log(JSON.stringify(summary));
    if (finalReadiness.recovery_required !== false || !['running', 'captured'].includes(finalReadiness.target?.execution_state)) throw new Error('Target requires operator reconciliation after the audit');
  }
  if (action === 'inspect-run') {
    const runs = page.locator('.run-history button');
    if (await runs.count() < 1) throw new Error('No retained run is available in the rendered history');
    const visibleHistory = await runs.allInnerTexts();
    await runs.first().click();
    await page.locator('.metadata').first().waitFor();
    await safeScreenshot(page, path.join(output, 'live-history-reopened.png'));
    const jsonDownload = page.waitForEvent('download');
    await page.getByRole('link', { name: 'Export JSON', exact: true }).click();
    await (await jsonDownload).saveAs(path.join(output, 'live-report.json'));
    const markdownDownload = page.waitForEvent('download');
    await page.getByRole('link', { name: 'Export Markdown', exact: true }).click();
    await (await markdownDownload).saveAs(path.join(output, 'live-report.md'));
    const raw = page.getByLabel(/Include raw bytes/).first();
    if (await raw.isChecked()) throw new Error('Raw bytes unexpectedly selected for export');
    await page.getByRole('button', { name: 'Export evidence bundle' }).click();
    await page.getByTestId('bundle-result').waitFor();
    const bundleResult = (await page.getByTestId('bundle-result').innerText()).trim();
    await safeScreenshot(page, path.join(output, 'live-bundle-export.png'));
    await page.getByRole('button', { name: 'AI Workbench', exact: true }).click();
    await page.getByRole('heading', { name: 'AI Firmware Workbench', exact: true }).waitFor();
    await safeScreenshot(page, path.join(output, 'live-workbench-with-run.png'));
    await page.getByRole('button', { name: 'Attack Lab', exact: true }).click();
    await page.getByRole('heading', { name: 'Attack Lab', exact: true }).waitFor();
    await safeScreenshot(page, path.join(output, 'live-attack-lab-with-run.png'));
    const summary = { history: visibleHistory, bundleResult, downloads: ['live-report.json', 'live-report.md'] };
    await writeFile(path.join(output, 'inspect-run-summary.json'), JSON.stringify(summary, null, 2), 'utf8');
    console.log(JSON.stringify(summary));
  }
  if (action === 'attack-plan' || action === 'workbench-accept') {
    const runResponse = await page.request.get('http://127.0.0.1:8000/api/runs');
    if (!runResponse.ok()) throw new Error(`Run inventory returned HTTP ${runResponse.status()}`);
    const runs = await runResponse.json();
    const source = runs.find(run => run.status === 'completed' && run.target_backend === 'openocd' && run.capture_count === 1 && run.bytes_requested === 64);
    if (!source) throw new Error('Approved completed 64-byte live run is unavailable');
    const sourceResponse = await page.request.get(`http://127.0.0.1:8000/api/runs/${source.run_id}`);
    if (!sourceResponse.ok()) throw new Error(`Source run lookup returned HTTP ${sourceResponse.status()}`);
    const sourceRun = await sourceResponse.json();
    const sourceCapture = sourceRun.captures?.[0];
    const sourceAcquisition = sourceRun.acquisitions?.find(item => item.evidence_id === sourceCapture?.evidence_id);
    const sourceRegister = sourceRun.registers?.find(item => item.evidence_id === sourceAcquisition?.register_evidence_id);
    if (sourceRun.run_id !== source.run_id || sourceRun.captures?.length !== 1 || !sourceAcquisition || !sourceRegister) throw new Error('Completed source run has no linked capture and register snapshot');
    await page.getByRole('button', { name: 'Attack Lab', exact: true }).click();
    await page.getByLabel('Evidence source').selectOption(source.run_id);
    await page.getByLabel('Security research instruction').fill('Review existing firmware integrity evidence from the completed 64-byte capture; do not access the target again.');
    await page.getByRole('button', { name: 'Get model recommendations' }).click();
    const module = page.locator('button.recommendation').filter({ hasText: 'Firmware integrity and persistence assessment' });
    await module.waitFor();
    await module.click();
    await page.getByLabel(/I confirm that I own or am authorized/).check();
    const [createdResponse] = await Promise.all([
      page.waitForResponse(response => safePath(response.url()) === '/api/attack-lab/plans' && response.request().method() === 'POST'),
      page.getByRole('button', { name: 'Create HITL plan' }).click(),
    ]);
    if (!createdResponse.ok()) throw new Error(`Plan creation returned HTTP ${createdResponse.status()}`);
    const created = await createdResponse.json();
    if (created.module_id !== 'firmware-integrity-assessment' || created.steps?.[0]?.operation !== 'evidence_review' || created.steps?.[1]?.operation !== 'firmware_patch_simulation') throw new Error('Plan operations differ from the reviewed nonphysical module');
    const capture = created.captures?.[0];
    const acquisition = created.acquisitions?.find(item => item.evidence_id === capture?.evidence_id);
    const registers = created.registers?.find(item => item.evidence_id === acquisition?.register_evidence_id);
    if (created.source_run_id !== source.run_id || created.captures?.length !== 1 || capture?.source_mode !== 'openocd' || !capture.evidence?.instructions?.length || !Number.isInteger(registers?.values?.pc)) throw new Error('Plan did not retain the source capture, decoded instructions, and linked registers');
    if (capture.evidence_id !== sourceCapture.evidence_id || capture.content_hash !== sourceCapture.content_hash || acquisition.register_evidence_id !== sourceAcquisition.register_evidence_id || registers.evidence_id !== sourceRegister.evidence_id) throw new Error('Plan evidence IDs or hash differ from the source run');
    if (acquisition.initial_state !== 'running' || acquisition.final_state !== 'running' || acquisition.restoration !== 'running' || acquisition.outcome_uncertain !== false || acquisition.recovery_required !== false || acquisition.error_code || acquisition.restoration_error_code) throw new Error('Source acquisition did not record a certain running-state restoration');
    const planId = created.plan_id;
    await safeScreenshot(page, path.join(output, 'live-plan-created.png'));
    await page.reload();
    await page.getByRole('button', { name: 'Attack Lab', exact: true }).click();
    await page.getByLabel('Saved Attack Lab plans').selectOption(planId);
    await page.locator('.execution').waitFor();
    await safeScreenshot(page, path.join(output, 'live-plan-reopened.png'));
    const [reviewResponse] = await Promise.all([
      page.waitForResponse(response => safePath(response.url()) === `/api/attack-lab/plans/${planId}/execute-next` && response.request().method() === 'POST'),
      page.getByRole('button', { name: 'Execute next approved step' }).click(),
    ]);
    if (!reviewResponse.ok()) throw new Error(`Evidence review returned HTTP ${reviewResponse.status()}`);
    const reviewed = await reviewResponse.json();
    if (reviewed.steps?.[0]?.status !== 'completed' || reviewed.steps?.[0]?.operation !== 'evidence_review' || !reviewed.steps?.[0]?.result?.includes('no target command sent')) throw new Error('Evidence-only step did not complete without target access');
    await page.getByRole('button', { name: 'Reject', exact: true }).click();
    await page.locator('.plan-state strong').getByText('simulation completed').waitFor();
    await safeScreenshot(page, path.join(output, 'live-plan-terminal.png'));
    const planJson = page.waitForEvent('download');
    await page.getByRole('link', { name: 'Export JSON', exact: true }).click();
    await (await planJson).saveAs(path.join(output, 'live-plan-report.json'));
    const planMarkdown = page.waitForEvent('download');
    await page.getByRole('link', { name: 'Export Markdown', exact: true }).click();
    await (await planMarkdown).saveAs(path.join(output, 'live-plan-report.md'));
    await page.getByRole('button', { name: 'AI Workbench', exact: true }).click();
    await page.getByLabel('JTAG evidence plan').selectOption(planId);
    await page.getByText('EVIDENCE LINKED', { exact: true }).waitFor();
    const captureView = (await page.locator('.capture-meta').innerText()).trim();
    const disassemblyView = (await page.locator('.instruction-table').innerText()).trim();
    const registerView = (await page.locator('.workbench-registers').innerText()).trim();
    if (!captureView.includes(`0x${capture.base_address.toString(16).padStart(8, '0')}`) || !disassemblyView.includes(capture.evidence.instructions[0].mnemonic) || !registerView.includes(`0x${registers.values.pc.toString(16).padStart(8, '0')}`) || !(await page.locator('.evidence-code small').innerText()).includes(capture.content_hash)) throw new Error('Workbench did not render the linked physical capture, hash, disassembly, and registers');
    const workbenchState = (await page.locator('.artifact-select').innerText()).trim();
    await safeScreenshot(page, path.join(output, 'live-workbench-selected-plan.png'));
    await page.getByRole('button', { name: 'Attack Lab', exact: true }).click();
    await page.getByLabel('Saved Attack Lab plans').selectOption(planId);
    const raw = page.getByLabel(/Include raw bytes/).first();
    if (await raw.isChecked()) throw new Error('Raw bytes unexpectedly selected for plan export');
    await page.getByRole('button', { name: 'Export evidence bundle' }).click();
    await page.getByTestId('bundle-result').waitFor();
    const bundleResult = (await page.getByTestId('bundle-result').innerText()).trim();
    if (!bundleResult.includes('INCOMPLETE · 0/1 captures with raw bytes')) throw new Error('Raw-free plan bundle did not report the expected incomplete verification');
    await safeScreenshot(page, path.join(output, 'live-plan-bundle-export.png'));
    if (action === 'workbench-accept') {
      const configResponse = await page.request.get('http://127.0.0.1:8000/api/config');
      const readinessResponse = await page.request.get('http://127.0.0.1:8000/api/readiness');
      if (!configResponse.ok() || !readinessResponse.ok()) throw new Error('Final authenticated config or readiness check failed');
      const config = await configResponse.json();
      const readiness = await readinessResponse.json();
      if (readiness.recovery_required !== false || readiness.target?.execution_state !== 'running' || readiness.live_ready !== true) throw new Error('Final target readiness or restoration check failed');
      const retainedResponse = await page.request.get(`http://127.0.0.1:8000/api/attack-lab/plans/${planId}`);
      if (!retainedResponse.ok()) throw new Error(`Retained plan lookup returned HTTP ${retainedResponse.status()}`);
      const retained = await retainedResponse.json();
      if (retained.plan_id !== planId || retained.source_run_id !== source.run_id || retained.captures?.[0]?.evidence_id !== capture.evidence_id) throw new Error('Run-linked plan was not retained after export');
      const summary = { source_run_id: source.run_id, plan_id: planId, capture_evidence_id: capture.evidence_id, acquisition_register_evidence_id: acquisition.register_evidence_id, register_evidence_id: registers.evidence_id, capture_address: capture.base_address, content_hash: capture.content_hash, decoded_instructions: capture.evidence.instructions.length, acquisition: { initial_state: acquisition.initial_state, final_state: acquisition.final_state, restoration: acquisition.restoration, outcome_uncertain: acquisition.outcome_uncertain, recovery_required: acquisition.recovery_required }, workbench_state: workbenchState, capture_view: captureView, register_names: Object.keys(registers.values), bundle_result: bundleResult, uart_config: { enabled: config.uart?.enabled, port: config.uart?.port, baud: config.uart?.baud }, final_readiness: { execution_state: readiness.target.execution_state, recovery_required: readiness.recovery_required, live_ready: readiness.live_ready }, downloads: ['live-plan-report.json', 'live-plan-report.md'], plan_retained: retained.plan_id === planId };
      await writeFile(path.join(output, 'workbench-accept-summary.json'), JSON.stringify(summary, null, 2), 'utf8');
      console.log(JSON.stringify(summary));
    } else {
      await page.getByRole('button', { name: 'Delete plan from memory' }).click();
      await page.getByRole('dialog', { name: 'Delete in-memory plan?' }).waitFor();
      await safeScreenshot(page, path.join(output, 'live-plan-delete-confirmation.png'));
      await page.getByRole('button', { name: 'Keep plan' }).click();
      if (!await page.getByLabel('Saved Attack Lab plans').locator(`option[value="${planId}"]`).count()) throw new Error('Keep plan unexpectedly removed the plan');
      await page.route(`**/api/attack-lab/plans/${planId}`, async route => {
        if (route.request().method() === 'DELETE') await new Promise(resolve => setTimeout(resolve, 500));
        await route.continue();
      });
      await page.getByRole('button', { name: 'Delete plan from memory' }).click();
      await page.getByRole('button', { name: 'Delete plan', exact: true }).click();
      await page.locator('.attack-progress').waitFor();
      await safeScreenshot(page, path.join(output, 'live-plan-delete-pending.png'));
      await page.getByText('Plan deleted from memory. Existing exports remain on disk.').waitFor();
      await safeScreenshot(page, path.join(output, 'live-plan-deleted.png'));
      const summary = { source_run_id: source.run_id, plan_id: planId, module_id: created.module_id, initial_status: created.status, reviewed_step: reviewed.steps[0].result, terminal_status: 'simulation_completed', workbench_state: workbenchState, deletion: 'confirmed', downloads: ['live-plan-report.json', 'live-plan-report.md'] };
      await writeFile(path.join(output, 'attack-plan-summary.json'), JSON.stringify(summary, null, 2), 'utf8');
      console.log(JSON.stringify(summary));
    }
  }
  if (action === 'auth-cycle') {
    await page.getByRole('button', { name: 'Investigation', exact: true }).click();
    const countBefore = await page.locator('.run-history button').count();
    if (countBefore < 1) throw new Error('Retained run is unavailable before sign-out');
    await page.locator('.run-history button').first().click();
    await page.locator('.metadata').first().waitFor();
    await page.getByRole('button', { name: 'Sign out' }).click();
    await page.getByLabel('Operator password').waitFor();
    if (await page.locator('.run-history button').count()) throw new Error('Retained evidence remains visible after sign-out');
    await safeScreenshot(page, path.join(output, 'live-signed-out.png'));
    await page.getByLabel('Operator password').fill(password);
    await page.getByRole('button', { name: 'Sign in', exact: true }).click();
    await page.getByTestId('readiness-verdict').waitFor();
    const countAfter = await page.locator('.run-history button').count();
    if (countAfter < 1) throw new Error('Retained run was not restored after normal sign-in');
    await safeScreenshot(page, path.join(output, 'live-signed-back-in.png'));
    const summary = { signed_out_local_evidence_cleared: true, signed_back_in: true, retained_runs_before: countBefore, retained_runs_after: countAfter };
    await writeFile(path.join(output, 'auth-cycle-summary.json'), JSON.stringify(summary, null, 2), 'utf8');
    console.log(JSON.stringify(summary));
  }
  if (action === 'uart-passive') {
    const response = await page.request.get('http://127.0.0.1:8000/api/config');
    if (!response.ok()) throw new Error(`UART configuration check returned HTTP ${response.status()}`);
    const config = await response.json();
    if (config.uart?.enabled !== true || config.uart?.port !== 'COM12' || config.uart?.baud !== 115200) throw new Error('Reviewed COM12/115200 UART auditor is not configured');
    await page.getByLabel('Fixed audit mode').selectOption('observe');
    const [auditResponse] = await Promise.all([
      page.waitForResponse(result => safePath(result.url()) === '/api/uart/audit' && result.request().method() === 'POST', { timeout: 110000 }),
      page.getByRole('button', { name: 'Arm UART audit' }).click(),
    ]);
    if (!auditResponse.ok()) throw new Error(`Passive UART observation returned HTTP ${auditResponse.status()}`);
    const result = await auditResponse.json();
    if (result.mode !== 'observe' || result.port !== 'COM12' || result.baud !== 115200) throw new Error('UART result does not match the reviewed passive configuration');
    const visible = await page.locator('.workspace .metadata, .workspace .notice').allInnerTexts();
    await safeScreenshot(page, path.join(output, 'live-uart-passive.png'));
    const summary = { mode: result.mode, status: result.status, port: result.port, baud: result.baud, transcript_bytes: result.transcript_bytes, transcript_hash: result.transcript_hash, boot_observed: result.boot_observed, uboot_prompt_obtained: result.uboot_prompt_obtained, configured_login_attempted: result.configured_login_attempted, errors: result.errors, visible_result: visible };
    await writeFile(path.join(output, 'uart-passive-summary.json'), JSON.stringify(summary, null, 2), 'utf8');
    console.log(JSON.stringify(summary));
  }
} finally {
  await writeFile(path.join(output, `browser-errors-${action}.json`), JSON.stringify(errors, null, 2), 'utf8');
  await browser.close();
}
