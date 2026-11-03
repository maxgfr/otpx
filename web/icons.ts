// Renders the PNG app icons from the same geometry as static/icons/icon.svg (no rasterizer needed).

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { deflateSync } from 'node:zlib';

type RGB = [number, number, number];
const ZINC: RGB = [0x18, 0x18, 0x1b];
const WHITE: RGB = [0xff, 0xff, 0xff];
const BLUE: RGB = [0x3b, 0x82, 0xf6];

function roundRect(x: number, y: number, x0: number, y0: number, w: number, h: number, r: number): number {
  const cx = Math.max(x0 + r, Math.min(x, x0 + w - r));
  const cy = Math.max(y0 + r, Math.min(y, y0 + h - r));
  return Math.hypot(x - cx, y - cy) - r; // < 0 inside
}

function pixel(x: number, y: number, maskable: boolean): [number, number, number, number] {
  // 64-unit design grid; maskable icons fill the square (no outer corner).
  const bg = maskable ? -1 : roundRect(x, y, 0, 0, 64, 64, 14);
  if (bg > 0.5) return [0, 0, 0, 0];
  let c: RGB = ZINC;
  if (roundRect(x, y, 14, 14, 36, 38, 4) < 0) c = WHITE;
  const d = Math.hypot(x - 25, y - 25);
  if (d < 6.5) c = d < 3.5 ? ZINC : BLUE;
  if (roundRect(x, y, 20, 37, 24, 5, 2.5) < 0) c = ZINC;
  return [...c, 255];
}

function png(size: number, maskable: boolean): Buffer {
  const s = 4; // supersampling
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let py = 0; py < size; py++) {
    raw[py * (size * 4 + 1)] = 0;
    for (let px = 0; px < size; px++) {
      const acc = [0, 0, 0, 0];
      for (let sy = 0; sy < s; sy++)
        for (let sx = 0; sx < s; sx++) {
          const u = ((px + (sx + 0.5) / s) / size) * 64;
          const v = ((py + (sy + 0.5) / s) / size) * 64;
          const p = pixel(maskable ? 32 + (u - 32) * 1.25 : u, maskable ? 32 + (v - 32) * 1.25 : v, maskable);
          for (let i = 0; i < 4; i++) acc[i] = (acc[i] ?? 0) + (p[i] ?? 0) * (i < 3 ? (p[3] ?? 0) / 255 : 1);
        }
      const a = (acc[3] ?? 0) / (s * s);
      const o = py * (size * 4 + 1) + 1 + px * 4;
      for (let i = 0; i < 3; i++) raw[o + i] = a > 0 ? Math.round((acc[i] ?? 0) / (s * s) / (a / 255)) : 0;
      raw[o + 3] = Math.round(a);
    }
  }
  const crcTable = Array.from({ length: 256 }, (_, n) => {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
  });
  const crc = (b: Buffer) => {
    let c = 0xffffffff;
    for (const x of b) c = (crcTable[(c ^ x) & 0xff] ?? 0) ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const chunk = (type: string, data: Buffer) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type), data]);
    const c = Buffer.alloc(4);
    c.writeUInt32BE(crc(td));
    return Buffer.concat([len, td, c]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr.set([8, 6, 0, 0, 0], 8);
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

const dir = join(import.meta.dir, 'static', 'icons');
writeFileSync(join(dir, 'icon-180.png'), png(180, true));
writeFileSync(join(dir, 'icon-192.png'), png(192, false));
writeFileSync(join(dir, 'icon-512.png'), png(512, true));
console.log('icons: written');
