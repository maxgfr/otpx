// Camera QR scanning: frames go to the core's QR decoder (the CLI's decoder too).

import { core } from './wasm';

export interface Scanner {
  stop(): void;
}

/** Starts scanning into `video`; `onCodes` gets every new decoded text. */
export async function scan(video: HTMLVideoElement, onCodes: (texts: string[]) => void): Promise<Scanner> {
  const stream = await navigator.mediaDevices.getUserMedia({
    video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } },
    audio: false,
  });
  video.srcObject = stream;
  video.setAttribute('playsinline', '');
  video.muted = true;
  await video.play();
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  const seen = new Set<string>();
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  const tick = () => {
    if (stopped || !ctx) return;
    const w = video.videoWidth;
    const hgt = video.videoHeight;
    if (w && hgt) {
      // QR codes stay readable at 720px; smaller frames decode much faster.
      const scale = Math.min(1, 720 / Math.max(w, hgt));
      canvas.width = Math.round(w * scale);
      canvas.height = Math.round(hgt * scale);
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
      try {
        const found = (
          JSON.parse(core.decodeQrRgba(img.width, img.height, new Uint8Array(img.data.buffer))) as string[]
        ).filter((t) => !seen.has(t));
        if (found.length) {
          for (const f of found) seen.add(f);
          onCodes(found);
        }
      } catch {
        /* unreadable frame */
      }
    }
    timer = setTimeout(tick, 180);
  };
  tick();
  return {
    stop() {
      stopped = true;
      if (timer) clearTimeout(timer);
      for (const t of stream.getTracks()) t.stop();
      video.srcObject = null;
    },
  };
}
