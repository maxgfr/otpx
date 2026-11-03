// End to end in a real browser: create, add, codes, copy, edit, share, lock, unlock, receive.
// SHOTS=dir also writes a screenshot of every screen (design review).

import { expect, type Page, test } from '@playwright/test';

const PW = 'correct horse battery staple';
const GH = 'otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub';
const AWS = 'otpauth://totp/AWS:root?secret=GEZDGNBVGY3TQOJQ&issuer=AWS&digits=8&algorithm=SHA256';
const BANK = 'otpauth://hotp/Bank:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0&issuer=Bank';

async function shot(page: Page, name: string): Promise<void> {
  const dir = process.env.SHOTS;
  if (!dir) return;
  await page.waitForTimeout(150);
  const scheme = process.env.DARK ? '-dark' : '';
  await page.screenshot({ path: `${dir}/${test.info().project.name}${scheme}-${name}.png`, fullPage: true });
}

async function createVault(page: Page): Promise<void> {
  await page.goto('/');
  await shot(page, '01-welcome');
  await page.getByRole('link', { name: /Create a vault/ }).click();
  await page.getByLabel('Master password').fill(PW);
  await page.getByLabel('Repeat it').fill(PW);
  await shot(page, '02-create');
  await page.getByRole('button', { name: 'Create the vault' }).click();
  await expect(page.getByRole('heading', { name: 'Your recovery code' })).toBeVisible();
  await shot(page, '03-recovery');
  await page.getByText('I wrote it down').click();
  await page.getByRole('button', { name: 'Continue' }).click();
}

test.use({ locale: 'en-US' });

test('create, add, read codes, edit, share, lock and unlock', async ({ page, context, browserName }) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
  if (browserName === 'chromium') await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await createVault(page);
  await expect(page.getByRole('heading', { name: 'No account yet' })).toBeVisible();
  await shot(page, '04-empty');

  await page.goto('/#/add');
  await page.getByRole('tab', { name: 'Paste' }).click();
  await page.getByLabel('Links').fill([GH, AWS, BANK].join('\n'));
  await page.getByRole('button', { name: 'Add', exact: true }).click();
  await expect(page.getByText('Added 3 accounts.')).toBeVisible();
  await shot(page, '05-added');

  await page.goto('/#/');
  const board = page.getByRole('list', { name: 'Accounts' });
  await expect(board.getByRole('listitem')).toHaveCount(3);
  // Codes come from the Rust core: 6 digits grouped for GitHub, 8 for AWS.
  await expect(board.getByRole('listitem').filter({ hasText: 'AWS' }).locator('.code')).toHaveText(
    /^\d{4} \d{4}$/,
  );
  await expect(board.getByRole('listitem').filter({ hasText: 'GitHub' }).locator('.code')).toHaveText(
    /^\d{3} \d{3}$/,
  );
  await expect(board.getByRole('listitem').filter({ hasText: 'Bank' }).locator('.code')).toHaveText(
    '••• •••',
  );
  await shot(page, '06-list');

  await page.getByRole('button', { name: 'Copy the code of GitHub (me@example.com)' }).click();
  await expect(page.locator('.tag.is-copied')).toHaveCount(1);
  if (browserName === 'chromium') {
    const clip = await page.evaluate(() => navigator.clipboard.readText());
    expect(clip).toMatch(/^\d{6}$/);
  }
  await shot(page, '07-copied');

  // Search keeps one tag; Enter copies it.
  await page.getByLabel('Search accounts').fill('aws');
  await expect(board.getByRole('listitem')).toHaveCount(1);
  await page.getByLabel('Search accounts').fill('');

  await page.getByRole('link', { name: 'Open GitHub (me@example.com)' }).click();
  await expect(page.getByRole('heading', { name: 'GitHub (me@example.com)' })).toBeVisible();
  await page.getByRole('button', { name: 'QR code' }).click();
  await expect(page.getByRole('img', { name: 'QR code' })).toBeVisible();
  await shot(page, '08-account');

  await page.getByRole('link', { name: 'Edit' }).click();
  await page.getByLabel('Note').fill('work org');
  await page.getByLabel('Tags').fill('work, dev');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('work org')).toBeVisible();

  await page.getByRole('link', { name: 'Share' }).click();
  await page.getByRole('button', { name: 'Make the link' }).click();
  const link = await page.locator('input.link-out').inputValue();
  expect(link).toMatch(/#s=1\./);
  await shot(page, '09-share');

  for (const [route, name] of [
    ['#/sync', '10-sync'],
    ['#/transfer', '11-transfer'],
    ['#/settings', '12-settings'],
    ['#/add', '13-add'],
  ] as const) {
    await page.goto(`/${route}`);
    await page.waitForSelector('h1');
    await shot(page, name);
  }

  // A PIN for this browser: set it, lock, a wrong PIN is counted, the right one opens.
  await page.goto('/#/settings');
  await page.getByLabel('New PIN (4 to 12 digits)').fill('482913');
  await page.getByRole('button', { name: 'Set a PIN' }).click();
  await expect(page.getByRole('button', { name: 'Remove the PIN' })).toBeVisible();
  await page.getByRole('button', { name: 'Lock' }).first().click();
  await expect(page.getByLabel('PIN')).toBeVisible();
  await page.getByLabel('PIN').fill('000000');
  await page.getByRole('button', { name: 'Unlock' }).click();
  await expect(page.getByText('Wrong PIN. 4 attempts left.')).toBeVisible();
  await page.getByLabel('PIN').fill('482913');
  await page.getByRole('button', { name: 'Unlock' }).click();
  await expect(page.getByRole('list', { name: 'Accounts' })).toBeVisible();

  await page.getByRole('button', { name: 'Lock' }).first().click();
  await page.getByRole('button', { name: 'Use the master password' }).click();
  await expect(page.getByRole('heading', { name: 'Unlock' })).toBeVisible();
  await page.getByLabel('Master password').fill('wrong');
  await page.getByRole('button', { name: 'Unlock' }).click();
  await expect(page.getByText(/Wrong password/)).toBeVisible();
  await shot(page, '14-unlock-error');
  await page.getByLabel('Master password').fill(PW);
  await page.getByRole('button', { name: 'Unlock' }).click();
  await expect(page.getByRole('list', { name: 'Accounts' }).getByRole('listitem')).toHaveCount(3);

  // HOTP: tapping reveals and copies the counter's code, the counter moves on.
  await page.getByRole('button', { name: 'Copy the code of Bank (alice)' }).click();
  await expect(page.locator('#toast')).toContainText(/Copied|Copy/);
  console.log('toast:', await page.locator('#toast').textContent());
  if (browserName === 'chromium')
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('755224');

  // A second browser opens the share link into its own vault.
  const other = await context.browser()?.newContext({ locale: 'en-US' });
  if (other) {
    const p2 = await other.newPage();
    await createVault(p2);
    await p2.goto(`/${link.slice(link.indexOf('#'))}`);
    await expect(p2.getByRole('heading', { name: 'Shared with you' })).toBeVisible();
    await shot(p2, '15-receive');
    await p2.getByRole('button', { name: 'Add to my vault' }).click();
    await expect(p2.getByText('Added 1 account.')).toBeVisible();
    await other.close();
  }
  // The offline cache registers under Trusted Types.
  await expect
    .poll(() => page.evaluate(async () => !!(await navigator.serviceWorker.getRegistration())))
    .toBe(true);
  expect(errors).toEqual([]);
});

test('English whatever the browser language, German from the settings, kept after a refresh', async ({
  browser,
}) => {
  const ctx = await browser.newContext({ locale: 'de-DE' });
  const page = await ctx.newPage();
  await page.goto('/');
  await expect(page.getByRole('link', { name: /Create a vault/ })).toBeVisible();
  await page.getByRole('link', { name: /Create a vault/ }).click();
  await page.getByLabel('Master password').fill('1234');
  await expect(page.getByText(/Digits only/)).toBeVisible();
  await page.getByLabel('Master password').fill(PW);
  await page.getByLabel('Repeat it').fill(PW);
  await page.getByRole('button', { name: 'Create the vault' }).click();
  await page.getByText('I wrote it down').click();
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.goto('/#/settings');
  await page.getByLabel('Language').selectOption('de');
  await expect(page.getByRole('heading', { name: 'Einstellungen' })).toBeVisible();
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Entsperren' })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('lang', 'de');
  await ctx.close();
});
