// Minimal Chromium launch test — exits 0 if the browser starts and loads a page.
import { chromium } from 'playwright';

try {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto('about:blank');
  await browser.close();
  process.exit(0);
} catch (err) {
  console.error('Chromium launch failed:', err.message);
  process.exit(1);
}
