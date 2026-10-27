import { test, expect } from './fixtures';
import { safeScreenshot } from '../scripts/safe-screenshot.mjs';

test('live operator screenshots mask rendered evidence and UART transcript', async ({ page }, testInfo) => {
  await page.setContent('<div class="inspect-grid">SRAM secret alpha</div><pre>UART secret alpha</pre><div class="string">String secret alpha</div><div class="finding">Finding secret alpha</div><div class="advice">Advice secret alpha</div><div class="step-result">Plan secret alpha</div>');
  const first = await safeScreenshot(page, testInfo.outputPath('masked-first.png'));
  const unmaskedFirst = await page.screenshot();
  await page.locator('.inspect-grid').evaluate(element => { element.textContent = 'SRAM secret omega'; });
  await page.locator('pre').evaluate(element => { element.textContent = 'UART secret omega'; });
  await page.locator('.string').evaluate(element => { element.textContent = 'String secret omega'; });
  await page.locator('.finding').evaluate(element => { element.textContent = 'Finding secret omega'; });
  await page.locator('.advice').evaluate(element => { element.textContent = 'Advice secret omega'; });
  await page.locator('.step-result').evaluate(element => { element.textContent = 'Plan secret omega'; });
  const second = await safeScreenshot(page, testInfo.outputPath('masked-second.png'));
  const unmaskedSecond = await page.screenshot();
  expect(first.equals(second)).toBe(true);
  expect(unmaskedFirst.equals(unmaskedSecond)).toBe(false);
});
