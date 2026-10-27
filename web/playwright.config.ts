import { defineConfig } from '@playwright/test';

// Browser tests never reuse the live 8000/8001 stack. The global setup launches scripts/test_stack.py,
// which allocates its own ports, forces MOCK target + SCRIPTED inference, strips inherited live
// configuration, and removes only the processes it started. baseURL is supplied per test from that
// stack (see e2e/fixtures.ts).
export default defineConfig({
  testDir: 'e2e',
  testMatch: '*.spec.ts',
  globalSetup: './e2e/global-setup.ts',
  workers: 1,
  fullyParallel: false,
  retries: 0,
  timeout: 60_000,
  use: { headless: true, viewport: { width: 1500, height: 1000 } },
});
