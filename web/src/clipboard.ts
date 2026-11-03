// Copies, cleared after a delay. Browsers only let a focused page write the clipboard, so a
// clear that comes due while the page is in the background happens when it is back. Where the
// page may read the clipboard (Chromium), only our own text is cleared; elsewhere the clipboard
// is cleared whatever it holds by then.

let clearTimer: ReturnType<typeof setTimeout> | null = null;
let pending: string | null = null;

async function clearNow(): Promise<boolean> {
  if (pending === null) return false;
  try {
    const now = await navigator.clipboard.readText().then(
      (t) => t,
      () => null,
    );
    if (now === null || now === pending) await navigator.clipboard.writeText('');
    pending = null;
    return true;
  } catch {
    return false;
  }
}

/** Copies `text`; `onCleared` runs once it is wiped. */
export async function copy(text: string, clearAfterSecs: number, onCleared?: () => void): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    return false;
  }
  pending = text;
  if (clearTimer) clearTimeout(clearTimer);
  if (clearAfterSecs > 0) {
    clearTimer = setTimeout(async () => {
      if (document.hasFocus() && (await clearNow())) {
        onCleared?.();
      } else {
        const back = async () => {
          window.removeEventListener('focus', back);
          if (await clearNow()) onCleared?.();
        };
        window.addEventListener('focus', back);
      }
    }, clearAfterSecs * 1000);
  }
  return true;
}
