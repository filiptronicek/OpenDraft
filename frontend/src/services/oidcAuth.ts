import { getApiBase } from '../config';
import { isWeb } from './platform';
import { scrubCapabilityUrl } from './capabilityUrl';
import { safeExternalHttpUrl } from './externalUrl';

const OIDC_RETURN_TO_KEY = 'opendraft:oidcReturnTo';
export const OIDC_CALLBACK_PATH = '/auth/oidc/callback';

/**
 * Only same-origin, app-relative destinations may survive an OIDC round trip.
 * In particular, reject protocol-relative URLs and the callback itself so a
 * stale sessionStorage value cannot create a redirect loop.
 */
export function safeOidcReturnTo(
  candidate: string | null | undefined,
  origin: string = window.location.origin,
): string {
  if (!candidate || !candidate.startsWith('/') || candidate.startsWith('//')) {
    return '/';
  }

  try {
    const url = new URL(candidate, origin);
    if (url.origin !== origin || url.pathname === OIDC_CALLBACK_PATH) return '/';
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return '/';
  }
}

export function currentOidcReturnTo(locationObject: Pick<Location, 'origin' | 'pathname' | 'search' | 'hash'> = window.location): string {
  return safeOidcReturnTo(
    `${locationObject.pathname}${locationObject.search}${locationObject.hash}`,
    locationObject.origin,
  );
}

export function rememberOidcReturnTo(
  returnTo: string,
  storage: Pick<Storage, 'setItem'> = window.sessionStorage,
): void {
  try {
    storage.setItem(OIDC_RETURN_TO_KEY, safeOidcReturnTo(returnTo));
  } catch {
    // Storage may be disabled in hardened/private browser contexts. The flow
    // still works; its safe fallback destination is the app root.
  }
}

/** Read and delete the destination in one operation so it cannot be replayed. */
export function consumeOidcReturnTo(
  storage: Pick<Storage, 'getItem' | 'removeItem'> = window.sessionStorage,
): string {
  try {
    const returnTo = storage.getItem(OIDC_RETURN_TO_KEY);
    storage.removeItem(OIDC_RETURN_TO_KEY);
    return safeOidcReturnTo(returnTo);
  } catch {
    return '/';
  }
}

export function getOidcStartUrl(apiBase: string = getApiBase()): string {
  return `${apiBase.replace(/\/+$/, '')}/auth/oidc/start`;
}

/** HTTPS is required for provider navigation; plain HTTP is development-only. */
export function safeOidcAuthorizationUrl(value: string): string | null {
  const safe = safeExternalHttpUrl(value);
  if (!safe) return null;
  const url = new URL(safe);
  if (url.protocol === 'https:') return safe;
  if (
    url.protocol === 'http:'
    && (url.hostname === 'localhost'
      || url.hostname === '127.0.0.1'
      || url.hostname === '[::1]'
      || url.hostname === '::1')
  ) {
    return safe;
  }
  return null;
}

/**
 * Begin the server-owned Authorization Code + PKCE flow. The browser follows
 * the backend's redirects; no provider or OpenDraft token is exposed to this
 * page or placed in a URL by the frontend.
 */
export function startOidcLogin(returnTo: string = currentOidcReturnTo()): void {
  if (!isWeb()) {
    throw new Error('Single sign-on is currently available in the OpenDraft web app.');
  }
  rememberOidcReturnTo(returnTo);
  window.location.assign(getOidcStartUrl());
}

export class OidcCallbackError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'OidcCallbackError';
    this.code = code;
  }
}

export function oidcCallbackErrorMessage(error: unknown): string {
  if (error instanceof OidcCallbackError) {
    switch (error.code) {
      case 'provider_error': return 'Sign-in was cancelled or rejected by the identity provider.';
      case 'invalid_state': return 'This sign-in request expired or was already used. Please try again.';
      case 'account_link_required': return 'An account with this email already exists. Sign in with its password, then link the identity provider in Account Settings.';
      case 'identity_already_linked': return 'That identity is already linked to another OpenDraft account.';
      case 'link_email_mismatch': return 'The email addresses in Authentik and OpenDraft must match before the accounts can be linked.';
      case 'oidc_unavailable': return 'Single sign-on is not available right now.';
      case 'invalid_response': return 'The identity provider returned an incomplete sign-in response. Please try again.';
      case 'authentication_failed': return 'The identity provider response could not be verified.';
      case 'missing_code': return 'This sign-in response is missing its one-time code. Please try again.';
      default: return 'Single sign-on failed. Please try again.';
    }
  }
  return error instanceof Error ? error.message : 'Single sign-on failed.';
}

interface CompleteOidcCallbackOptions<Result> {
  search: string;
  pathname: string;
  exchange: (code: string) => Promise<Result>;
  historyObject?: Parameters<typeof scrubCapabilityUrl>[1];
  storage?: Pick<Storage, 'getItem' | 'removeItem'>;
}

/**
 * Scrub the handoff URL and consume its saved destination synchronously,
 * before the one-time code is sent over the network.
 */
export async function completeOidcCallback<Result>({
  search,
  pathname,
  exchange,
  historyObject = window.history,
  storage = window.sessionStorage,
}: CompleteOidcCallbackOptions<Result>): Promise<{ result: Result; returnTo: string }> {
  const query = new URLSearchParams(search.startsWith('?') ? search.slice(1) : search);
  // Deliberately read only these two fields. Provider tokens or arbitrary
  // redirect targets are never accepted by the frontend callback.
  const code = query.get('code') || '';
  const error = query.get('error') || '';

  scrubCapabilityUrl(pathname, historyObject);
  const returnTo = consumeOidcReturnTo(storage);

  if (error) {
    const safeErrorCode = error.length <= 128 ? error : 'unknown_error';
    throw new OidcCallbackError(safeErrorCode, 'Single sign-on failed');
  }
  if (!code) {
    throw new OidcCallbackError(
      'missing_code',
      'Missing one-time sign-in code',
    );
  }
  if (code.length > 512) {
    throw new OidcCallbackError('invalid_response', 'Invalid one-time sign-in code');
  }

  return { result: await exchange(code), returnTo };
}
