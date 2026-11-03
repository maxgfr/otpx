// DOM building without innerHTML (Trusted Types are enforced by the page's CSP).

type Child = Node | string | number | false | null | undefined | Child[];
type Attrs = Record<string, string | number | boolean | EventListener | null | undefined>;

function append(el: Element, child: Child): void {
  if (child === null || child === undefined || child === false) return;
  if (Array.isArray(child)) {
    for (const c of child) append(el, c);
    return;
  }
  el.append(child instanceof Node ? child : String(child));
}

/** `h('button', { class: 'x', onclick }, 'Label')`. */
export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith('on') && typeof v === 'function') {
      el.addEventListener(k.slice(2), v);
    } else if (v === true) {
      el.setAttribute(k, '');
    } else {
      el.setAttribute(k, String(v));
    }
  }
  for (const c of children) append(el, c);
  return el;
}

/** Replaces the children of `el`. */
export function mount(el: Element, ...children: Child[]): void {
  el.replaceChildren();
  for (const c of children) append(el, c);
}

const SVG = 'http://www.w3.org/2000/svg';

// One stroke family: 24-unit grid, 1.75 stroke, round caps and joins.
const PATHS: Record<string, string[]> = {
  search: ['M10.5 17a6.5 6.5 0 1 0 0-13 6.5 6.5 0 0 0 0 13Z', 'm15.5 15.5 4.5 4.5'],
  plus: ['M12 5v14', 'M5 12h14'],
  lock: ['M6.5 11h11v9h-11z', 'M8.5 11V8a3.5 3.5 0 0 1 7 0v3'],
  copy: ['M9 9h10v11H9z', 'M15 9V5H5v11h4'],
  qr: [
    'M4 4h6v6H4z',
    'M14 4h6v6h-6z',
    'M4 14h6v6H4z',
    'M14 14h2v2h-2z',
    'M18 18h2v2h-2z',
    'M18 14h2',
    'M14 18v2',
  ],
  share: ['M12 15V4', 'm8 8 4-4 4 4', 'M5 13v6h14v-6'],
  edit: ['M4 20h4L19 9l-4-4L4 16v4Z', 'm13.5 6.5 4 4'],
  trash: ['M5 7h14', 'M9 7V4h6v3', 'M7 7l1 13h8l1-13'],
  sync: ['M19 8a7.5 7.5 0 0 0-13.4 1', 'M5 16a7.5 7.5 0 0 0 13.4-1', 'M19 4v4h-4', 'M5 20v-4h4'],
  settings: [
    'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z',
    'M19 12a7 7 0 0 0-.1-1.2l2-1.5-2-3.4-2.3.9a7 7 0 0 0-2-1.2L14 3h-4l-.6 2.6a7 7 0 0 0-2 1.2l-2.3-.9-2 3.4 2 1.5a7 7 0 0 0 0 2.4l-2 1.5 2 3.4 2.3-.9a7 7 0 0 0 2 1.2L10 21h4l.6-2.6a7 7 0 0 0 2-1.2l2.3.9 2-3.4-2-1.5c.07-.4.1-.8.1-1.2Z',
  ],
  back: ['M19 12H5', 'm11 6-6 6 6 6'],
  chevron: ['m9 6 6 6-6 6'],
  camera: ['M4 8h3l2-3h6l2 3h3v11H4z', 'M12 17a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z'],
  image: ['M4 5h16v14H4z', 'm4 16 5-5 4 4 2-2 5 5', 'M15.5 9.5h.01'],
  download: ['M12 4v11', 'm7 10 5 5 5-5', 'M5 20h14'],
  upload: ['M12 20V9', 'm7 14 5-5 5 5', 'M5 4h14'],
  key: ['M8 15a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z', 'M12 11h9', 'M18 11v3', 'M21 11v2'],
  fingerprint: [
    'M7.5 6.5A7 7 0 0 1 19 12v1',
    'M5 10a7 7 0 0 0-.4 2.3c0 1.6.3 3.1.9 4.5',
    'M9 12a3 3 0 0 1 6 0c0 2.6-.5 5-1.5 7',
    'M12 12c0 2.8-.7 5.4-2 7.6',
    'M16.8 16.5c-.2 1.3-.6 2.6-1.1 3.8',
  ],
  check: ['m5 12.5 4.5 4.5L19 7'],
  close: ['M6 6l12 12', 'M18 6 6 18'],
  star: ['m12 4 2.4 5 5.5.7-4 3.8 1 5.5-4.9-2.7-4.9 2.7 1-5.5-4-3.8 5.5-.7Z'],
  more: ['M5.5 12h.01', 'M12 12h.01', 'M18.5 12h.01'],
  link: [
    'M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1',
    'M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1',
  ],
  folder: ['M3.5 6.5h6l2 2h9v10h-17z'],
  cloud: ['M7 18h10a4 4 0 0 0 .5-8A6 6 0 0 0 6 9.5 4.3 4.3 0 0 0 7 18Z'],
  alert: ['M12 4 3 19h18L12 4Z', 'M12 10v4', 'M12 16.5h.01'],
  eye: [
    'M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z',
    'M12 14.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5Z',
  ],
  terminal: ['M4 5h16v14H4z', 'm7.5 9.5 3 2.5-3 2.5', 'M12.5 15h4'],
};

/** An icon from the set, decorative unless `label` is given. */
export function icon(name: keyof typeof PATHS, label?: string): SVGSVGElement {
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('class', 'icon');
  if (label) {
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', label);
  } else {
    svg.setAttribute('aria-hidden', 'true');
  }
  for (const d of PATHS[name] ?? []) {
    const p = document.createElementNS(SVG, 'path');
    p.setAttribute('d', d);
    svg.append(p);
  }
  return svg;
}

export type IconName = keyof typeof PATHS;

/** Text where `backticked` parts become <code> nodes. */
export function rich(text: string): (string | HTMLElement)[] {
  return text
    .split(/(`[^`]+`)/)
    .filter(Boolean)
    .map((part) => (part.startsWith('`') && part.endsWith('`') ? h('code', {}, part.slice(1, -1)) : part));
}

/** A data: URL for an SVG document (QR codes), shown with <img> so no markup is injected. */
export function svgUrl(svg: string): string {
  const bytes = new TextEncoder().encode(svg);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return `data:image/svg+xml;base64,${btoa(bin)}`;
}

/** Groups a code for reading: 123 456, 1234 5678. */
export function groupCode(code: string): string {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}
