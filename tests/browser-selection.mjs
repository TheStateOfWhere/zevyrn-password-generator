import {openSettings,closeSettings} from './browser-dialog.mjs';
// Real-browser regression check using the locked development-only Playwright.
// Only deterministic public fixtures are generated.
import assert from 'node:assert/strict';
import { screenshotDirectory } from './browser-artifacts.mjs';
const screenshotPath = await screenshotDirectory('selection');
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.KEYSMITH_PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url));
const server = spawn(process.execPath, ['scripts/serve.mjs'], { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
let browser;
try {
  await new Promise((resolve, reject) => {
    server.stdout.once('data', resolve);
    server.once('error', reject);
    server.once('exit', () => reject(new Error('Local preview server exited')));
  });
  browser = await chromium.launch({ headless: true, ...(process.env.KEYSMITH_BROWSER_PATH ? { executablePath: process.env.KEYSMITH_BROWSER_PATH } : {}) });
  const context = await browser.newContext({ viewport: { width: 1280, height: 1000 }, permissions: ['clipboard-read', 'clipboard-write'] });
  const page = await context.newPage();
  await page.addInitScript(() => {
    let index = 0;
    const fixture = [0, 0, 0, 0, 8, 0, 8, 0, 8];
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: {
      getRandomValues(buffer) { buffer[0] = fixture[index++ % fixture.length]; return buffer; },
    } });
  });
  await page.goto('http://127.0.0.1:4173/');
  const advanced = page.locator('#advanced');
  const summary = advanced.locator('summary');
  assert.equal(await advanced.evaluate(el => el.open), false);
  assert.equal(await page.locator('#suffix').isVisible(), false);
  assert.equal(await page.locator('#count').isVisible(), true);
  assert.equal(await page.locator('#generate').isVisible(), true);
  await openSettings(page);await summary.focus(); await page.keyboard.press('Enter');
  assert.equal(await advanced.evaluate(el => el.open), true);
  assert.equal(await page.locator('#suffix').inputValue(), '6');
  await openSettings(page);await page.locator('#suffix').fill('7');
  await openSettings(page);await summary.focus(); await page.keyboard.press('Space');
  assert.equal(await advanced.evaluate(el => el.open), false);
  assert.equal(await page.locator('#suffix').inputValue(), '7');
  await openSettings(page);await summary.click();
  await openSettings(page);await page.locator('#suffix').fill('5');
  assert.equal(await page.locator('#generate').isDisabled(), true);
  assert.ok((await page.locator('#strength-note').textContent()).includes('Generation blocked'));
  await openSettings(page);await page.locator('#suffix').fill('6');
  await openSettings(page);await page.locator('#min-word').fill('');
  await openSettings(page);await summary.click();
  await page.locator('#settings-form').evaluate(form => form.requestSubmit());
  assert.equal(await advanced.evaluate(el => el.open), true);
  await openSettings(page);await page.locator('#min-word').fill('4');
  await openSettings(page);await summary.click();
  await closeSettings(page);await page.locator('#generate').click();
  assert.ok((await page.locator('.password-list').boundingBox()).height < 420, 'Prominent password output remains bounded');
  assert.ok((await page.locator('.results').boundingBox()).height < 700, 'Spacious one-password output remains bounded');
  await page.screenshot({ path: screenshotPath('desktop-one.png'), fullPage: true });
  await openSettings(page);await summary.click();
  await page.screenshot({ path: screenshotPath('advanced-expanded.png'), fullPage: true });
  await openSettings(page);await summary.click();
  await closeSettings(page);
  const text = page.locator('.password').first();
  const original = await text.textContent();
  const parts = original.split('.');
  assert.ok(parts.length === 4 && !/\s/.test(original), 'Fixture password text is exact');
  assert.equal(await text.evaluate(el => getComputedStyle(el).userSelect), 'text');
  const selected = () => page.evaluate(() => window.getSelection().toString());
  const segments = text.locator('.segment');
  await segments.nth(0).dblclick();
  assert.ok(await selected() === parts[0], 'Double-click selects only the first word');
  await segments.nth(1).dblclick();
  assert.ok(await selected() === parts[1], 'Double-click selects only the uppercase word');
  async function position(segment, offset) {
    return segments.nth(segment).evaluate((el, offset) => {
      const range = document.createRange(); range.setStart(el.firstChild, offset); range.collapse(true);
      const rect = range.getBoundingClientRect();
      return { x: rect.x, y: rect.y + rect.height / 2 };
    }, offset);
  }
  async function drag(a, b) {
    await page.evaluate(()=>getSelection()?.removeAllRanges());
    await page.mouse.move(a.x, a.y); await page.mouse.down();
    await page.mouse.move(b.x, b.y, { steps: 12 }); await page.mouse.up();
  }
  await drag(await position(0, 1), await position(0, 3));
  assert.ok(await selected() === parts[0].slice(1, 3), 'Drag selects a portion of a dictionary word');
  await page.keyboard.press('Control+c');
  assert.ok(await page.evaluate(() => navigator.clipboard.readText()) === parts[0].slice(1, 3), 'Ctrl+C copies exactly the selected portion');
  await drag(await position(0, 1), await position(1, 2));
  assert.ok(await selected() === `${parts[0].slice(1)}.${parts[1].slice(0, 2)}`, 'Cross-component drag preserves the separator without whitespace');
  await drag(await position(3, 0), await position(3, parts[3].length));
  assert.ok(await selected() === parts[3], 'Complete suffix is independently selectable');
  await page.locator('.component-disclosure summary').first().click();
  const copyButtons = page.locator('.component-copy button');
  for (let i = 0; i < 4; i++) {
    await copyButtons.nth(i).click();
    await page.waitForFunction(() => document.querySelector('#status').textContent.startsWith('Copied.'));
    assert.ok(await page.evaluate(() => navigator.clipboard.readText()) === parts[i], 'Component copy matches exactly');
  }
  await page.getByRole('button', { name: 'Copy password 1', exact: true }).click();
  assert.ok(await page.evaluate(() => navigator.clipboard.readText()) === original, 'Full copy preserves complete password');
  await copyButtons.nth(1).focus(); await page.keyboard.press('Enter');
  assert.ok(await page.evaluate(() => navigator.clipboard.readText()) === parts[1], 'Component copy supports keyboard activation');
  await closeSettings(page);await page.locator('#manual').check();
  assert.ok(await text.textContent() === original, 'Large text keeps the exact password');
  await segments.nth(1).dblclick();
  assert.ok(await selected() === parts[1], 'Native word selection also works in large text mode');
  await closeSettings(page);await page.locator('#manual').uncheck();
  await page.evaluate(() => Object.defineProperty(navigator.clipboard, 'writeText', { configurable: true, value: async () => { throw new Error('Fixture clipboard denial'); } }));
  await page.locator('.component-disclosure summary').first().click();
  await copyButtons.nth(0).click();
  await page.waitForFunction(() => document.querySelector('#status').textContent.startsWith('Clipboard unavailable.'));
  assert.ok(!(await page.locator('#status').textContent()).includes(original), 'Failure feedback does not expose password');

  await page.setViewportSize({ width: 390, height: 844 });await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await closeSettings(page);
  assert.ok(await text.textContent() === original, 'Narrow viewport preserves exact text');
  await text.scrollIntoViewIfNeeded();
  await drag(await position(0, 0), await position(3, parts[3].length));
  assert.ok(await selected() === original, 'Native wrapped selection: '+JSON.stringify(await page.evaluate(()=>({length:getSelection().toString().length,whitespace:/\\s/.test(getSelection().toString()),expected:document.querySelector(".password").textContent.length}))));
  await page.keyboard.press('Control+c');
  assert.ok(await page.evaluate(() => navigator.clipboard.readText()) === original, 'Ctrl+C across wrapped lines preserves the original string');
  await page.evaluate(()=>getSelection()?.removeAllRanges());
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Narrow layout has no horizontal overflow');
  await page.setViewportSize({ width: 1280, height: 1000 });await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await closeSettings(page);
  await closeSettings(page);await page.locator('#count').selectOption('5');
  await closeSettings(page);await page.locator('#generate').click();
  assert.equal(await page.locator('.password-row').count(), 5);
  assert.equal(await page.locator('.component-copy button').count(), 20);
  await page.screenshot({ path: screenshotPath('desktop-multiple.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await closeSettings(page);
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Multiple rows have no horizontal overflow');
  for (const disclosure of await page.locator('.component-disclosure').all()) await disclosure.locator('summary').click();
  for (const button of await page.locator('.component-copy button').all()) {
    const bounds = await button.boundingBox();
    assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 390, 'Component controls remain inside narrow viewport');
  }
  const targets = await page.locator('button:not(:disabled), .toggle, summary').evaluateAll(elements => elements.map(el => ({width:el.getBoundingClientRect().width,height:el.getBoundingClientRect().height})).filter(r => r.width && r.height));
  assert.ok(targets.every(r => r.width >= 44 && r.height >= 44), 'Mobile controls must have 44px touch targets');
  await page.screenshot({ path: screenshotPath('mobile-multiple.png'), fullPage: true });
  await openSettings(page);await summary.click();
  await openSettings(page);await page.locator('#suffix').fill('64');
  await openSettings(page);await summary.click(); await closeSettings(page);await page.locator('#generate').click();
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Maximum suffix length wraps without overflow');
  assert.equal(await page.locator('.password .segment').first().evaluate(el => getComputedStyle(el.parentElement).userSelect), 'text');
  await page.setViewportSize({ width: 320, height: 844 });await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await closeSettings(page);
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Maximum suffix length fits 320px viewport');
  await closeSettings(page);await page.locator('#manual').check();
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Large-text maximum suffix fits narrow viewport');
  // Current Zevyrn UI: real rendered columns, exact text and maximum batch size.
  await closeSettings(page);await page.locator('#theme').selectOption('zevyrn');
  await closeSettings(page);await page.locator('#manual').uncheck();
  await openSettings(page);await summary.click(); await openSettings(page);await page.locator('#suffix').fill('6'); await openSettings(page);await summary.click();
  await closeSettings(page);await page.locator('#count').selectOption('1'); await closeSettings(page);await page.locator('#generate').click();
  assert.equal(await page.locator('h1').textContent(), 'Secure passwords. Easy on the eyes.');
  for (const width of [1280,768,390,320]) {
    await page.setViewportSize({width,height:1000});await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await closeSettings(page);
    await page.evaluate(() => scrollTo(0,0));
    assert.equal(await page.locator('#settings-disclosure').isVisible(),false,'Settings do not occupy a permanent column');
    assert.equal(await page.locator('#passwords').evaluate(e=>e.classList.contains('focus')),true);
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'UI has no page overflow');
    await openSettings(page);await openSettings(page);await page.locator('#profile').focus();
    assert.notEqual(await page.locator('#profile').evaluate(e=>getComputedStyle(e).outlineStyle),'none');
    assert.equal(await page.getByRole('combobox',{name:'Password profile',exact:true}).count(),1);
    await page.evaluate(() => scrollTo(0,0));
    await page.screenshot({path:screenshotPath('ui-zevyrn-'+width+'.png'),fullPage:true});
  }
  await closeSettings(page);await page.locator('#count').selectOption('20');
  await openSettings(page);await summary.click(); await openSettings(page);await page.locator('#suffix').fill('64'); await openSettings(page);await summary.click();
  await closeSettings(page);await page.locator('#generate').click();
  assert.equal(await page.locator('.password-row').count(),20);
  const batch=await page.locator('.password').allTextContents();
  assert.ok(batch.every(value=>value.split('.').length===4 && !/\s/.test(value)));
  for (const width of [320,390,768,1280]) {
    await page.setViewportSize({width,height:1000});await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await closeSettings(page);
    for (const manual of [false,true]) {
      await closeSettings(page);await page.locator('#manual').setChecked(manual);
      assert.deepEqual(await page.locator('.password').allTextContents(),batch,'Manual mode preserves all twenty exact passwords');
      assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'Twenty long passwords never overflow the page');
    }
  }
  console.log('PASS: Edge native selection/copy, advanced disclosure/validation, compact one-row output, multiple-row controls, 320px/390px layouts, and maximum suffix wrapping. Screenshots contain deterministic public fixtures only.');
} finally {
  await browser?.close();
  server.kill();
}
