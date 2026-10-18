import * as crypto from 'crypto';

export const OIDC_TRANSACTION_COOKIE = 'opendraft_oidc_tx';
export const OIDC_COOKIE_PATH = '/api/auth/oidc';
export const OIDC_TRANSACTION_TTL_MS = 5 * 60 * 1000;
export const OIDC_HANDOFF_TTL_MS = 60 * 1000;

export interface OidcTransaction {
  nonce: string;
  codeVerifier: string;
  returnTo: string;
  linkUserId: string | null;
}

interface StoredTransaction extends OidcTransaction {
  bindingDigest: Buffer;
  expiresAt: number;
}

export interface OidcHandoff {
  userId: string;
  returnTo: string;
}

interface StoredHandoff extends OidcHandoff {
  bindingDigest: Buffer;
  expiresAt: number;
}

function randomOpaque(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('base64url');
}

function digest(value: string): Buffer {
  return crypto.createHash('sha256').update(value, 'utf8').digest();
}

function equalDigest(left: Buffer, right: Buffer): boolean {
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

export function pkceChallenge(verifier: string): string {
  return crypto.createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

export function parseCookie(header: string | undefined, name: string): string | null {
  if (!header) return null;
  for (const pair of header.split(';')) {
    const separator = pair.indexOf('=');
    if (separator < 0) continue;
    if (pair.slice(0, separator).trim() !== name) continue;
    const value = pair.slice(separator + 1).trim();
    try {
      return decodeURIComponent(value);
    } catch {
      return null;
    }
  }
  return null;
}

export function oidcTransactionCookie(value: string, maxAgeSeconds: number): string {
  return [
    `${OIDC_TRANSACTION_COOKIE}=${encodeURIComponent(value)}`,
    `Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`,
    `Path=${OIDC_COOKIE_PATH}`,
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
  ].join('; ');
}

export function clearOidcTransactionCookie(): string {
  return oidcTransactionCookie('', 0);
}

/**
 * Allow navigation within the configured frontend only. The server stores the
 * relative path and always resolves it against APP_URL; absolute and
 * scheme-relative redirect targets are discarded.
 */
export function safeReturnTo(candidate: unknown): string {
  if (typeof candidate !== 'string' || !candidate.startsWith('/') || candidate.startsWith('//')) {
    return '/';
  }
  try {
    const parsed = new URL(candidate, 'https://opendraft.invalid');
    if (
      parsed.origin !== 'https://opendraft.invalid'
      || parsed.pathname === '/auth/oidc/callback'
    ) return '/';
    return `${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return '/';
  }
}

export class OidcStateStore {
  private readonly transactions = new Map<string, StoredTransaction>();
  private readonly handoffs = new Map<string, StoredHandoff>();

  constructor(
    private readonly transactionTtlMs = OIDC_TRANSACTION_TTL_MS,
    private readonly handoffTtlMs = OIDC_HANDOFF_TTL_MS,
    private readonly maxEntries = 10_000,
  ) {}

  createTransaction(
    returnTo: string,
    linkUserId: string | null = null,
    now = Date.now(),
  ): {
    state: string;
    nonce: string;
    codeVerifier: string;
    codeChallenge: string;
    cookieValue: string;
  } {
    this.prune(now);
    this.dropOldestIfFull(this.transactions);

    const state = randomOpaque();
    const nonce = randomOpaque();
    // 64 random bytes encode to an 86-character RFC 7636 verifier.
    const codeVerifier = randomOpaque(64);
    const cookieValue = randomOpaque();
    this.transactions.set(digest(state).toString('hex'), {
      nonce,
      codeVerifier,
      returnTo: safeReturnTo(returnTo),
      linkUserId,
      bindingDigest: digest(cookieValue),
      expiresAt: now + this.transactionTtlMs,
    });
    return {
      state,
      nonce,
      codeVerifier,
      codeChallenge: pkceChallenge(codeVerifier),
      cookieValue,
    };
  }

  consumeTransaction(
    state: string,
    cookieValue: string | null,
    now = Date.now(),
  ): OidcTransaction | null {
    const key = digest(state).toString('hex');
    const transaction = this.transactions.get(key);
    // Delete before validation so every callback attempt is one-use, including
    // expired or incorrectly bound attempts.
    this.transactions.delete(key);
    if (!transaction || transaction.expiresAt <= now || !cookieValue) return null;
    if (!equalDigest(transaction.bindingDigest, digest(cookieValue))) return null;
    return {
      nonce: transaction.nonce,
      codeVerifier: transaction.codeVerifier,
      returnTo: transaction.returnTo,
      linkUserId: transaction.linkUserId,
    };
  }

  createHandoff(
    userId: string,
    returnTo: string,
    now = Date.now(),
  ): { code: string; cookieValue: string } {
    this.prune(now);
    this.dropOldestIfFull(this.handoffs);
    const code = randomOpaque();
    const cookieValue = randomOpaque();
    this.handoffs.set(digest(code).toString('hex'), {
      userId,
      returnTo: safeReturnTo(returnTo),
      bindingDigest: digest(cookieValue),
      expiresAt: now + this.handoffTtlMs,
    });
    return { code, cookieValue };
  }

  consumeHandoff(
    code: string,
    cookieValue: string | null,
    now = Date.now(),
  ): OidcHandoff | null {
    const key = digest(code).toString('hex');
    const handoff = this.handoffs.get(key);
    this.handoffs.delete(key);
    if (!handoff || handoff.expiresAt <= now || !cookieValue) return null;
    if (!equalDigest(handoff.bindingDigest, digest(cookieValue))) return null;
    return { userId: handoff.userId, returnTo: handoff.returnTo };
  }

  private prune(now: number): void {
    for (const [key, value] of this.transactions) {
      if (value.expiresAt <= now) this.transactions.delete(key);
    }
    for (const [key, value] of this.handoffs) {
      if (value.expiresAt <= now) this.handoffs.delete(key);
    }
  }

  private dropOldestIfFull<T>(entries: Map<string, T>): void {
    if (entries.size < this.maxEntries) return;
    const oldest = entries.keys().next().value as string | undefined;
    if (oldest) entries.delete(oldest);
  }
}

export const oidcStateStore = new OidcStateStore();
