// Copying codes, cleared after the vault's delay (when the page still has focus: browsers
// only let a focused page write the clipboard).

let clearTimer: ReturnType<typeof setTimeout> | null = null;
let pending: string | null = null;

async function clearNow(): Promise<boolean> {
  if (pending === null) return false;
  try {
    // Only clear what we put there.
    const now = await navigator.clipboard.readText().catch(() => pending);
    if (now === pending) await navigator.clipboard.writeText('');
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
        // Not focused: clear as soon as the page is back.
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
