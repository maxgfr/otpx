// Serves dist/ on http://localhost:5173 with the headers GitHub Pages cannot set (tests, preview).

import { existsSync } from 'node:fs';
import { join, normalize } from 'node:path';

const dist = join(import.meta.dir, 'dist');
const port = Number(process.env.PORT ?? 5173);

Bun.serve({
  port,
  hostname: '127.0.0.1',
  async fetch(req) {
    const url = new URL(req.url);
    let path = normalize(decodeURIComponent(url.pathname)).replace(/^(\.\.[/\\])+/, '');
    if (path.endsWith('/')) path += 'index.html';
    const file = join(dist, path);
    if (!file.startsWith(dist) || !existsSync(file)) return new Response('not found', { status: 404 });
    return new Response(Bun.file(file), {
      headers: {
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'Cache-Control': 'no-store',
      },
    });
  },
});
console.log(`otpx web preview on http://localhost:${port}/`);
