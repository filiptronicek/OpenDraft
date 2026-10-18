export function captureCapabilityParams<const Key extends string>(
  keys: readonly Key[],
  hash: string,
  search: string,
): Record<Key, string> {
  const fragment = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash);
  const query = new URLSearchParams(search.startsWith('?') ? search.slice(1) : search);
  return Object.fromEntries(
    keys.map((key) => [key, fragment.get(key) || query.get(key) || '']),
  ) as Record<Key, string>;
}

interface HistoryReplacement {
  state: unknown;
  replaceState(data: unknown, unused: string, url?: string | URL | null): void;
}

/** Remove query/fragment capabilities without retaining them in history state. */
export function scrubCapabilityUrl(
  pathname: string,
  historyObject: HistoryReplacement = window.history,
): void {
  historyObject.replaceState(historyObject.state, '', pathname);
}
