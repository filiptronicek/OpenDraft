import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  completeOidcCallback,
  consumeOidcReturnTo,
  currentOidcReturnTo,
  getOidcStartUrl,
  OidcCallbackError,
  oidcCallbackErrorMessage,
  rememberOidcReturnTo,
  safeOidcAuthorizationUrl,
  safeOidcReturnTo,
} from './oidcAuth';

describe('OIDC browser handoff', () => {
  beforeEach(() => {
    sessionStorage.clear();
  });

  it('keeps same-origin relative return paths', () => {
    expect(safeOidcReturnTo('/project/abc?tab=notes#scene-2', 'https://scripts.example'))
      .toBe('/project/abc?tab=notes#scene-2');
    expect(currentOidcReturnTo({
      origin: 'https://scripts.example',
      pathname: '/settings',
      search: '?section=account',
      hash: '',
    })).toBe('/settings?section=account');
  });

  it.each([
    'https://attacker.example/steal',
    '//attacker.example/steal',
    '/\\attacker.example/steal',
    '/auth/oidc/callback?code=replay',
    '',
  ])('rejects unsafe or looping return path %j', (candidate) => {
    expect(safeOidcReturnTo(candidate, 'https://scripts.example')).toBe('/');
  });

  it('consumes the remembered return path exactly once', () => {
    const removeItem = vi.spyOn(sessionStorage, 'removeItem');
    rememberOidcReturnTo('/settings');

    expect(consumeOidcReturnTo()).toBe('/settings');
    expect(removeItem).toHaveBeenCalledWith('opendraft:oidcReturnTo');
    expect(consumeOidcReturnTo()).toBe('/');
  });

  it('falls back safely when browser session storage is unavailable', () => {
    const unavailable = {
      getItem: () => { throw new Error('blocked'); },
      removeItem: vi.fn(),
    };
    expect(consumeOidcReturnTo(unavailable)).toBe('/');
  });

  it('scrubs the query and consumes return state before exchanging the handoff', async () => {
    const events: string[] = [];
    const historyObject = {
      state: null,
      replaceState: vi.fn(() => { events.push('scrub'); }),
    };
    const storage = {
      getItem: vi.fn(() => '/settings'),
      removeItem: vi.fn(() => { events.push('consume-return'); }),
    };
    const exchange = vi.fn(async (code: string) => {
      events.push('exchange');
      return { code };
    });

    const completed = completeOidcCallback({
      search: '?code=one-use&access_token=must-be-ignored&returnTo=https://attacker.example',
      pathname: '/auth/oidc/callback',
      historyObject,
      storage,
      exchange,
    });

    expect(events).toEqual(['scrub', 'consume-return', 'exchange']);
    expect(historyObject.replaceState).toHaveBeenCalledWith(
      null,
      '',
      '/auth/oidc/callback',
    );
    await expect(completed).resolves.toEqual({
      result: { code: 'one-use' },
      returnTo: '/settings',
    });
    expect(exchange).toHaveBeenCalledWith('one-use');
  });

  it('builds the backend start endpoint without query parameters', () => {
    expect(getOidcStartUrl('https://scripts.example/api/'))
      .toBe('https://scripts.example/api/auth/oidc/start');
  });

  it('allows secure provider navigation and HTTP only on loopback', () => {
    expect(safeOidcAuthorizationUrl('https://auth.example/authorize?state=opaque'))
      .toBe('https://auth.example/authorize?state=opaque');
    expect(safeOidcAuthorizationUrl('http://localhost:9000/authorize'))
      .toBe('http://localhost:9000/authorize');
    expect(safeOidcAuthorizationUrl('http://auth.example/authorize')).toBeNull();
    expect(safeOidcAuthorizationUrl('javascript:alert(1)')).toBeNull();
  });

  it.each([
    'account_link_required',
    'identity_already_linked',
    'link_email_mismatch',
    'invalid_state',
    'provider_error',
    'invalid_response',
    'authentication_failed',
    'oidc_unavailable',
  ])('maps callback error code %s to a user-facing message', (code) => {
    const message = oidcCallbackErrorMessage(new OidcCallbackError(code, code));
    expect(message).not.toBe(code);
    expect(message.length).toBeGreaterThan(20);
  });

  it('never renders an unknown callback query error verbatim', () => {
    const untrusted = '<img src=x onerror=alert(1)>';
    expect(oidcCallbackErrorMessage(new OidcCallbackError(untrusted, untrusted)))
      .toBe('Single sign-on failed. Please try again.');
  });

  it('bounds oversized callback errors and never attempts an exchange', async () => {
    const exchange = vi.fn();
    await expect(completeOidcCallback({
      search: `?error=${'x'.repeat(10_000)}`,
      pathname: '/auth/oidc/callback',
      exchange,
      historyObject: { state: null, replaceState: vi.fn() },
      storage: { getItem: vi.fn(() => null), removeItem: vi.fn() },
    })).rejects.toMatchObject({ code: 'unknown_error' });
    expect(exchange).not.toHaveBeenCalled();
  });
});
