export function safeScreenshot(page, filename) {
  return page.screenshot({
    path: filename,
    fullPage: true,
    mask: [page.locator('.inspect-grid, .finding, .evidence-code, .advice, .patch-preview, .recommendation p, .attack-step p, .step-result, .approval-log p, .timeline .event p, pre, .string')],
    maskColor: '#142330',
  });
}
