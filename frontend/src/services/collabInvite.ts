export interface ParsedCollabInvite {
  token: string;
  collabServerUrl: string | null;
}

export interface ParseCollabInviteOptions {
  configuredCollabUrl: string;
  frontendBaseUrls: string[];
}

function originOf(value: string): string | null {
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

function websocketOrigin(url: URL): string {
  const protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${url.host}`;
}

/** Parse both current SPA invite links and legacy direct-collab links. */
export function parseCollabInvite(
  input: string,
  options: ParseCollabInviteOptions,
): ParsedCollabInvite {
  const trimmed = input.trim();
  const match =
    trimmed.match(/\/collab#([A-Za-z0-9_-]+)(?:[/?#]|$)/)
    || trimmed.match(/\/collab\/([A-Za-z0-9_-]+)(?:[/?#]|$)/);
  if (match) {
    try {
      const url = new URL(trimmed);
      const knownFrontendOrigins = new Set(
        options.frontendBaseUrls.map(originOf).filter((value): value is string => Boolean(value)),
      );
      if (knownFrontendOrigins.has(url.origin)) {
        const configured = options.configuredCollabUrl.replace(/\/+$/, '');
        return {
          token: match[1],
          collabServerUrl: configured || `${websocketOrigin(url)}/collab-server`,
        };
      }
      // Compatibility for old links whose origin was the standalone Node host.
      return { token: match[1], collabServerUrl: websocketOrigin(url) };
    } catch {
      return { token: match[1], collabServerUrl: null };
    }
  }

  if (!trimmed.includes('/') && trimmed.length > 10) {
    return { token: trimmed, collabServerUrl: null };
  }
  return { token: trimmed, collabServerUrl: null };
}

export interface BuildCollabInviteOptions {
  isTauri: boolean;
  browserOrigin: string;
  apiBase: string;
}

export function readCollabRouteToken(
  pathToken: string | undefined,
  pathname: string,
  hash: string,
): string | undefined {
  if (pathToken) return pathToken;
  if (pathname.replace(/\/+$/, '') !== '/collab' || hash.length <= 1) return undefined;
  try {
    const token = decodeURIComponent(hash.slice(1));
    return /^[A-Za-z0-9_-]+$/.test(token) ? token : undefined;
  } catch {
    return undefined;
  }
}

function trustedWebsocketOrigin(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.protocol !== 'ws:' && url.protocol !== 'wss:') return null;
    return url.origin;
  } catch {
    return null;
  }
}

export function isTrustedCollabTransport(
  selectedWsUrl: string,
  configuredWsUrl: string,
): boolean {
  const selectedOrigin = trustedWebsocketOrigin(selectedWsUrl);
  const configuredOrigin = trustedWebsocketOrigin(configuredWsUrl);
  return Boolean(selectedOrigin && configuredOrigin && selectedOrigin === configuredOrigin);
}

export function decodeJwtPayload(accessToken: string): { exp?: number } | null {
  try {
    const segment = accessToken.split('.')[1];
    if (!segment) return null;
    const normalized = segment.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

/** Never disclose the account JWT to a transport selected by an invite URL. */
export function buildCollabProviderToken(
  inviteToken: string,
  accessToken: string | null | undefined,
  selectedWsUrl: string,
  configuredWsUrl: string,
  now = Date.now(),
): string {
  if (!accessToken || !isTrustedCollabTransport(selectedWsUrl, configuredWsUrl)) {
    return inviteToken;
  }
  const payload = decodeJwtPayload(accessToken);
  if (!payload?.exp || payload.exp * 1000 <= now) return inviteToken;
  return `jwt:${accessToken}|invite:${inviteToken}`;
}

/**
 * Invite links always target the frontend SPA. In Tauri, the webview origin is
 * not public, so derive the frontend server root from the configured cloud API.
 * The capability stays in the URL fragment and never reaches HTTP access logs.
 */
export function buildCollabInviteUrl(
  token: string,
  options: BuildCollabInviteOptions,
): string {
  const base = (options.isTauri
    ? options.apiBase.replace(/\/api\/?$/, '')
    : options.browserOrigin
  ).replace(/\/+$/, '');
  return `${base}/collab#${encodeURIComponent(token)}`;
}
