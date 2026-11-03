// IndexedDB key-value store. Only ciphertext and non-secret preferences are written here:
// the origin is shared with other sites of maxgfr.github.io.

const DB = 'otpx';
const STORE = 'kv';

export interface Backing {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown): Promise<void>;
  del(key: string): Promise<void>;
  clear(): Promise<void>;
}

function req<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

let dbp: Promise<IDBDatabase> | null = null;

function db(): Promise<IDBDatabase> {
  dbp ??= new Promise((resolve, reject) => {
    const open = indexedDB.open(DB, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(STORE);
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
  });
  return dbp;
}

async function tx(mode: IDBTransactionMode): Promise<IDBObjectStore> {
  return (await db()).transaction(STORE, mode).objectStore(STORE);
}

export const idb: Backing = {
  async get<T>(key: string) {
    return (await req((await tx('readonly')).get(key))) as T | undefined;
  },
  async set(key, value) {
    await req((await tx('readwrite')).put(value, key));
  },
  async del(key) {
    await req((await tx('readwrite')).delete(key));
  },
  async clear() {
    await req((await tx('readwrite')).clear());
  },
};

/** An in-memory store (tests). */
export function memory(): Backing {
  const m = new Map<string, unknown>();
  return {
    async get<T>(k: string) {
      return m.get(k) as T | undefined;
    },
    async set(k, v) {
      m.set(k, v);
    },
    async del(k) {
      m.delete(k);
    },
    async clear() {
      m.clear();
    },
  };
}
