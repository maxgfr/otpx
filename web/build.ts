// Builds the web app into dist/: hashed bundle, stylesheet and wasm, SRI in index.html,
// a service worker caching exactly those files, and the PWA manifest.
// Run scripts/build-web.sh from the repository root first (it builds pkg/ with wasm-pack).

import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const root = import.meta.dir;
const dist = join(root, 'dist');
const pkgWasm = join(root, 'pkg', 'otpx_bg.wasm');
if (!existsSync(pkgWasm)) {
  console.error('build: web/pkg is missing; run scripts/build-web.sh (wasm-pack) first');
  process.exit(1);
}

const short = (data: Uint8Array | string) => createHash('sha256').update(data).digest('hex').slice(0, 12);
const sri = (data: Uint8Array | string) => `sha384-${createHash('sha384').update(data).digest('base64')}`;

rmSync(dist, { recursive: true, force: true });
mkdirSync(join(dist, 'icons'), { recursive: true });

const wasm = readFileSync(pkgWasm);
const wasmName = `otpx-${short(wasm)}.wasm`;
writeFileSync(join(dist, wasmName), wasm);

const js = await Bun.build({
  entrypoints: [join(root, 'src', 'main.ts')],
  target: 'browser',
  format: 'esm',
  minify: true,
  sourcemap: 'none',
  define: { OTPX_WASM: JSON.stringify(wasmName) },
});
if (!js.success) {
  for (const l of js.logs) console.error(l);
  process.exit(1);
}
const entry = js.outputs.find((o) => o.kind === 'entry-point');
if (!entry) throw new Error('no entry point');
const jsText = await entry.text();
if (/innerHTML|outerHTML|insertAdjacentHTML|document\.write\(|\beval\(|new Function\(/.test(jsText)) {
  console.error('build: the bundle uses an HTML or code sink; Trusted Types would block it');
  process.exit(1);
}
const jsName = `app-${short(jsText)}.js`;
writeFileSync(join(dist, jsName), jsText);

const css = readFileSync(join(root, 'static', 'app.css'), 'utf8');
const cssName = `app-${short(css)}.css`;
writeFileSync(join(dist, cssName), css);

const html = readFileSync(join(root, 'static', 'index.html'), 'utf8')
  .replace('%CSS%', cssName)
  .replace('%CSS_SRI%', sri(css))
  .replace('%JS%', jsName)
  .replace('%JS_SRI%', sri(jsText));
writeFileSync(join(dist, 'index.html'), html);

cpSync(join(root, 'static', 'icons'), join(dist, 'icons'), { recursive: true });
writeFileSync(
  join(dist, 'manifest.webmanifest'),
  JSON.stringify(
    {
      name: 'otpx',
      short_name: 'otpx',
      description: 'Your 2FA codes in an encrypted vault you keep where you choose.',
      start_url: './',
      scope: './',
      display: 'standalone',
      background_color: '#fafafa',
      theme_color: '#18181b',
      icons: [
        { src: 'icons/icon.svg', sizes: 'any', type: 'image/svg+xml' },
        { src: 'icons/icon-192.png', sizes: '192x192', type: 'image/png' },
        { src: 'icons/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any maskable' },
      ],
    },
    null,
    2,
  ),
);

const assets = ['./', 'index.html', jsName, cssName, wasmName, 'manifest.webmanifest', 'icons/icon.svg'];
for (const p of ['icons/icon-180.png', 'icons/icon-192.png', 'icons/icon-512.png'])
  if (existsSync(join(dist, p))) assets.push(p);
const version = short(assets.join('|') + jsText + css);
writeFileSync(
  join(dist, 'sw.js'),
  `// otpx offline cache: the app shell only. Never caches API calls or other origins.
const CACHE = 'otpx-${version}';
const ASSETS = ${JSON.stringify(assets)};
self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k.startsWith('otpx-') && k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()),
  );
});
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin || url.pathname.includes('/api/')) return;
  if (e.request.mode === 'navigate') {
    e.respondWith(fetch(e.request).catch(() => caches.match('index.html')));
    return;
  }
  e.respondWith(caches.match(e.request).then((hit) => hit || fetch(e.request)));
});
`,
);
writeFileSync(join(dist, '.nojekyll'), '');
const kb = (n: number) => `${(n / 1024).toFixed(0)} KiB`;
console.log(
  `build: dist/ ready (js ${kb(jsText.length)}, css ${kb(css.length)}, wasm ${kb(wasm.length)}, cache ${version})`,
);
