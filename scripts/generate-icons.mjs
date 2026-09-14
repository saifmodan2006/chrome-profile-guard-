/**
 * Icon generator for Chrome Profile Guard — dependency-free (uses Node's
 * built-in zlib to encode PNGs). Renders a flat, Chrome-inspired mark: a blue
 * rounded tile with a white browser window and a small lock. No gradients.
 *
 * Usage:  node scripts/generate-icons.mjs
 * Output: icons/icon-16.png, icon-32.png, icon-48.png, icon-128.png
 */

import { deflateSync } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'icons');
mkdirSync(OUT, { recursive: true });

const BLUE = [26, 115, 232];
const WHITE = [255, 255, 255];
const BAR = [232, 240, 254];

/* ---------- geometry (normalized 0..1) ---------- */

function insideRoundedRect(x, y, x0, y0, x1, y1, r) {
  if (x < x0 || x > x1 || y < y0 || y > y1) return false;
  const inX = x >= x0 + r && x <= x1 - r;
  const inY = y >= y0 + r && y <= y1 - r;
  if (inX || inY) return true;
  const cx = x < x0 + r ? x0 + r : x1 - r;
  const cy = y < y0 + r ? y0 + r : y1 - r;
  return (x - cx) ** 2 + (y - cy) ** 2 <= r * r;
}
function insideCircle(x, y, cx, cy, r) {
  return (x - cx) ** 2 + (y - cy) ** 2 <= r * r;
}

/** Return [r,g,b,a] (0..255) for a normalized point, compositing the layers. */
function sample(x, y) {
  let color = null;

  // 1. blue tile
  if (insideRoundedRect(x, y, 0.02, 0.06, 0.98, 0.94, 0.20)) color = BLUE;

  // 2. white browser window
  if (insideRoundedRect(x, y, 0.22, 0.28, 0.78, 0.72, 0.06)) color = WHITE;
  // 2a. top toolbar strip (inset so it stays within rounded corners)
  if (insideRoundedRect(x, y, 0.24, 0.30, 0.76, 0.38, 0.02)) color = BAR;

  // 3. lock shackle (upper half of a blue ring)
  if (y <= 0.50 && insideCircle(x, y, 0.50, 0.50, 0.075) && !insideCircle(x, y, 0.50, 0.50, 0.05)) {
    color = BLUE;
  }
  // 4. lock body
  if (insideRoundedRect(x, y, 0.40, 0.50, 0.60, 0.66, 0.025)) color = BLUE;
  // 5. keyhole
  if (insideCircle(x, y, 0.50, 0.565, 0.018)) color = WHITE;

  return color ? [color[0], color[1], color[2], 255] : [0, 0, 0, 0];
}

/* ---------- rasterize with 4x supersampling ---------- */

function render(size) {
  const S = 4;
  const px = Buffer.alloc(size * size * 4);
  for (let oy = 0; oy < size; oy++) {
    for (let ox = 0; ox < size; ox++) {
      let ar = 0, ag = 0, ab = 0, aa = 0;
      for (let sy = 0; sy < S; sy++) {
        for (let sx = 0; sx < S; sx++) {
          const nx = (ox + (sx + 0.5) / S) / size;
          const ny = (oy + (sy + 0.5) / S) / size;
          const [r, g, b, a] = sample(nx, ny);
          const af = a / 255;
          ar += r * af; ag += g * af; ab += b * af; aa += af;
        }
      }
      const n = S * S;
      const outA = aa / n;
      const i = (oy * size + ox) * 4;
      if (aa > 0) {
        px[i] = Math.round(ar / aa);
        px[i + 1] = Math.round(ag / aa);
        px[i + 2] = Math.round(ab / aa);
      }
      px[i + 3] = Math.round(outA * 255);
    }
  }
  return px;
}

/* ---------- PNG encoding ---------- */

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const typeBuf = Buffer.from(type, 'ascii');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crc]);
}
function encodePng(size, rgba) {
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 6;  // color type RGBA
  ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;

  // filter byte 0 per scanline
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  const idat = deflateSync(raw, { level: 9 });
  return Buffer.concat([sig, chunk('IHDR', ihdr), chunk('IDAT', idat), chunk('IEND', Buffer.alloc(0))]);
}

/* ---------- write ---------- */

for (const size of [16, 32, 48, 128]) {
  const png = encodePng(size, render(size));
  writeFileSync(join(OUT, `icon-${size}.png`), png);
  console.log(`wrote icon-${size}.png (${png.length} bytes)`);
}
