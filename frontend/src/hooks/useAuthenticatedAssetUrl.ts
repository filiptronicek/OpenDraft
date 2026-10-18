import { useEffect, useMemo, useState } from 'react';
import { useSettingsStore } from '../stores/settingsStore';
import {
  acquireAuthenticatedAssetUrl,
  isDirectAssetUrl,
} from '../services/authenticatedAssetUrl';

interface AuthenticatedAssetUrlState {
  url: string;
  loading: boolean;
  error: Error | null;
}

interface ResolvedState {
  key: string;
  url: string;
  error: Error | null;
}

/** Resolve a protected asset URL to a browser-loadable, ref-counted blob URL. */
export function useAuthenticatedAssetUrl(
  sourceUrl: string | null | undefined,
): AuthenticatedAssetUrlState {
  const userId = useSettingsStore((state) => state.collabAuth.user?.id ?? null);
  const key = useMemo(
    () => JSON.stringify([userId, sourceUrl || '']),
    [sourceUrl, userId],
  );
  const directUrl = sourceUrl && isDirectAssetUrl(sourceUrl) ? sourceUrl : '';
  const [resolved, setResolved] = useState<ResolvedState>({ key: '', url: '', error: null });

  useEffect(() => {
    if (!sourceUrl || directUrl) return;

    const lease = acquireAuthenticatedAssetUrl(sourceUrl, userId);
    let active = true;

    lease.url.then(
      (url) => {
        if (active) setResolved({ key, url, error: null });
      },
      (error: unknown) => {
        if (active) {
          setResolved({
            key,
            url: '',
            error: error instanceof Error ? error : new Error(String(error)),
          });
        }
      },
    );

    return () => {
      active = false;
      lease.release();
    };
  }, [directUrl, key, sourceUrl, userId]);

  if (!sourceUrl) return { url: '', loading: false, error: null };
  if (directUrl) return { url: directUrl, loading: false, error: null };
  if (resolved.key !== key) return { url: '', loading: true, error: null };
  return { url: resolved.url, loading: false, error: resolved.error };
}
