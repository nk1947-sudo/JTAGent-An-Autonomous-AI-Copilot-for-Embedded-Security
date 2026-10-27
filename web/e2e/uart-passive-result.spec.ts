import { test, expect, signIn } from './fixtures';

test('zero-byte passive UART result stays inconclusive in the rendered dashboard', async ({ page }) => {
  await page.route('**/api/config', async route => {
    const upstream = await route.fetch();
    if (!upstream.ok()) return route.fulfill({ response: upstream });
    const config = await upstream.json();
    config.uart = { enabled: true, port: 'COM12', baud: 115200 };
    await route.fulfill({ json: config });
  });
  await page.route('**/api/uart/audit', route => route.fulfill({ json: {
    mode: 'observe', status: 'failed', port: 'COM12', baud: 115200,
    transcript_bytes: 0, transcript_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    transcript_excerpt: '', observations: [], errors: ['no_uart_data_received'],
    boot_observed: false, uboot_prompt_obtained: false,
    configured_login_succeeded: false, root_without_additional_prompt: false,
  } }));
  await signIn(page);
  await page.getByLabel('Fixed audit mode').selectOption('observe');
  await page.getByRole('button', { name: 'Arm UART audit' }).click();
  await expect(page.getByText('No UART bytes received; console readiness remains unverified.')).toBeVisible();
  await expect(page.getByText('No configured exposure observed')).toHaveCount(0);
  await expect(page.locator('.workspace .metadata').last()).toContainText('0 bytes');
});
