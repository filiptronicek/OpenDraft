import { authedFetch } from './authedFetch';

export interface AuthenticatedAssetUrlLease {
  url: Promise<string>;
  release: () => void;
}

type FetchBlob = (url: string) => Promise<Blob>;
type CreateObjectUrl = (blob: Blob) => string;
type RevokeObjectUrl = (url: string) => void;

interface CacheEntry {
  key: string;
  references: number;
  state: 'pending' | 'ready';
  objectUrl: string | null;
  promise: Promise<string>;
}

/** URLs that the browser/WebView can load directly without HTTP credentials. */
export function isDirectAssetUrl(url: string): boolean {
  const normalized = url.trim().toLowerCase();
  if (
    normalized.startsWith('data:') ||
    normalized.startsWith('blob:') ||
    normalized.startsWith('asset:') ||
    normalized.startsWith('tauri:')
  ) {
    return true;
  }

  try {
    const parsed = new URL(url);
    // Tauri's convertFileSrc uses asset://localhost on some platforms and
    // http(s)://asset.localhost on others.
    return parsed.hostname.toLowerCase() === 'asset.localhost';
  } catch {
    return false;
  }
}

/**
 * Ref-counted object-URL cache for protected assets.
 *
 * Concurrent leases for the same user and source share one fetch. The user id
 * is part of the cache key so a sign-out/sign-in on a shared device can never
 * reuse bytes fetched for the previous account.
 */
export class AuthenticatedAssetUrlCache {
  private readonly entries = new Map<string, CacheEntry>();

  private readonly fetchBlob: FetchBlob;
  private readonly createObjectUrl: CreateObjectUrl;
  private readonly revokeObjectUrl: RevokeObjectUrl;

  constructor(
    fetchBlob: FetchBlob,
    createObjectUrl: CreateObjectUrl,
    revokeObjectUrl: RevokeObjectUrl,
  ) {
    this.fetchBlob = fetchBlob;
    this.createObjectUrl = createObjectUrl;
    this.revokeObjectUrl = revokeObjectUrl;
  }

  acquire(userId: string | null, sourceUrl: string): AuthenticatedAssetUrlLease {
    if (isDirectAssetUrl(sourceUrl)) {
      return { url: Promise.resolve(sourceUrl), release: () => {} };
    }

    const key = JSON.stringify([userId, sourceUrl]);
    let entry = this.entries.get(key);

    if (!entry) {
      const created: CacheEntry = {
        key,
        references: 0,
        state: 'pending',
        objectUrl: null,
        promise: Promise.resolve(''),
      };

      let blobPromise: Promise<Blob>;
      try {
        // Start immediately so the bearer token read by authedFetch belongs to
        // the same authenticated user that forms this entry's cache key.
        blobPromise = this.fetchBlob(sourceUrl);
      } catch (error: unknown) {
        blobPromise = Promise.reject(error);
      }

      created.promise = blobPromise
        .then((blob) => {
          const objectUrl = this.createObjectUrl(blob);
          created.state = 'ready';
          created.objectUrl = objectUrl;

          // All consumers may have unmounted while the request was pending.
          if (created.references === 0) this.dispose(created);
          return objectUrl;
        })
        .catch((error: unknown) => {
          if (this.entries.get(key) === created) this.entries.delete(key);
          throw error;
        });

      entry = created;
      this.entries.set(key, created);
    }

    entry.references += 1;
    let released = false;

    return {
      url: entry.promise,
      release: () => {
        if (released) return;
        released = true;
        entry!.references = Math.max(0, entry!.references - 1);
        if (entry!.references === 0 && entry!.state === 'ready') {
          this.dispose(entry!);
        }
      },
    };
  }

  private dispose(entry: CacheEntry): void {
    if (this.entries.get(entry.key) === entry) this.entries.delete(entry.key);
    if (entry.objectUrl) {
      const objectUrl = entry.objectUrl;
      entry.objectUrl = null;
      this.revokeObjectUrl(objectUrl);
    }
  }
}

const authenticatedAssetUrlCache = new AuthenticatedAssetUrlCache(
  async (sourceUrl) => {
    const response = await authedFetch(sourceUrl);
    if (!response.ok) {
      throw new Error(`Asset request failed with status ${response.status}`);
    }
    return response.blob();
  },
  (blob) => URL.createObjectURL(blob),
  (url) => URL.revokeObjectURL(url),
);

export function acquireAuthenticatedAssetUrl(
  sourceUrl: string,
  userId: string | null,
): AuthenticatedAssetUrlLease {
  return authenticatedAssetUrlCache.acquire(userId, sourceUrl);
}
