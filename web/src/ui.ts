// Shared pieces of the interface: toast, fields, buttons, the tag eyelet, notices.

import { h, type IconName, icon } from './dom';

let toastTimer: ReturnType<typeof setTimeout> | null = null;

/** A short status line, announced to screen readers. */
export function toast(text: string, kind: 'info' | 'error' = 'info'): void {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = text;
  el.dataset.kind = kind;
  el.classList.add('is-shown');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('is-shown'), kind === 'error' ? 7000 : 3600);
}

export function button(
  label: string,
  onclick: (e: Event) => void,
  opts: {
    kind?: 'primary' | 'plain' | 'danger' | 'quiet';
    icon?: IconName;
    type?: 'button' | 'submit';
    disabled?: boolean;
  } = {},
): HTMLButtonElement {
  return h(
    'button',
    {
      type: opts.type ?? 'button',
      class: `btn btn-${opts.kind ?? 'plain'}`,
      onclick: onclick as EventListener,
      disabled: opts.disabled ?? false,
    },
    opts.icon ? icon(opts.icon) : null,
    h('span', {}, label),
  );
}

let fieldSeq = 0;

export function field(
  label: string,
  input: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement,
  hint?: string,
): HTMLDivElement {
  const id = input.id || `f${++fieldSeq}`;
  input.id = id;
  const hintEl = hint ? h('p', { class: 'hint', id: `${id}-hint` }, hint) : null;
  if (hintEl) input.setAttribute('aria-describedby', hintEl.id);
  return h('div', { class: 'field' }, h('label', { for: id }, label), input, hintEl);
}

export function input(attrs: Record<string, string | boolean> = {}): HTMLInputElement {
  return h('input', { type: 'text', autocomplete: 'off', spellcheck: 'false', ...attrs });
}

export function select(options: [string, string][], value: string): HTMLSelectElement {
  return h('select', {}, ...options.map(([v, l]) => h('option', { value: v, selected: v === value }, l)));
}

/** A notice in a plate: what happens to the data, or what went wrong. */
export function notice(text: string, kind: 'proof' | 'warn' | 'error' = 'proof'): HTMLParagraphElement {
  return h(
    'p',
    { class: `notice notice-${kind}`, role: kind === 'error' ? 'alert' : null },
    kind === 'proof' ? null : icon('alert'),
    h('span', {}, text),
  );
}

/** The punched eyelet whose brass rim is the countdown. */
export function eyelet(): HTMLSpanElement {
  return h('span', { class: 'eyelet', 'aria-hidden': 'true' }, h('span', { class: 'eyelet-hole' }));
}

/** Updates an eyelet: `remaining` of `period` seconds. */
export function setEyelet(el: Element | null, remaining: number, period: number): void {
  if (!(el instanceof HTMLElement)) return;
  const p = period > 0 ? Math.max(0, Math.min(1, remaining / period)) : 1;
  el.style.setProperty('--left', String(p));
  el.classList.toggle('is-ending', period > 0 && remaining <= 5);
  el.classList.toggle('is-counter', period === 0);
}

/** A page heading with the back link. */
export function pageHead(title: string, back?: { href: string; label: string }): HTMLElement {
  return h(
    'div',
    { class: 'page-head' },
    back ? h('a', { class: 'back', href: back.href }, icon('back'), h('span', {}, back.label)) : null,
    h('h1', { tabindex: '-1' }, title),
  );
}

/** Reads a File as bytes. */
export async function bytesOf(f: Blob): Promise<Uint8Array> {
  return new Uint8Array(await f.arrayBuffer());
}

/** Downloads `content` as a file. */
export function download(name: string, content: string, type = 'text/plain'): void {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = h('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
