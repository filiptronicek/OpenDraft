export interface AuthenticatedUrlTrustOptions {
  apiBases: string[];
  collabWsUrl: string;
  pageHref: string;
}

function httpOrigin(value: string, pageHref: string): string | null {
  try {
    const parsed = new URL(value, pageHref);
    if (parsed.protocol === 'ws:') parsed.protocol = 'http:';
    if (parsed.protocol === 'wss:') parsed.protocol = 'https:';
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    return parsed.origin;
  } catch {
    return null;
  }
}

/** Bearer credentials may leave the app only for configured API transports. */
export function isTrustedAuthenticatedUrl(
  url: string,
  options: AuthenticatedUrlTrustOptions,
): boolean {
  const targetOrigin = httpOrigin(url, options.pageHref);
  if (!targetOrigin) return false;

  const trustedOrigins = new Set<string>();
  for (const base of options.apiBases) {
    const origin = httpOrigin(base, options.pageHref);
    if (origin) trustedOrigins.add(origin);
  }
  const collabOrigin = httpOrigin(options.collabWsUrl, options.pageHref);
  if (collabOrigin) trustedOrigins.add(collabOrigin);
  return trustedOrigins.has(targetOrigin);
}

export function shouldRefreshAuthentication(
  url: string,
  status: number,
  hasRefreshToken: boolean,
  options: AuthenticatedUrlTrustOptions,
): boolean {
  return status === 401
    && hasRefreshToken
    && isTrustedAuthenticatedUrl(url, options);
}
