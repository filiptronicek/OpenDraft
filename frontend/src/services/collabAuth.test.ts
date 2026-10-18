import { afterEach, describe, expect, it, vi } from 'vitest';
import { useSettingsStore } from '../stores/settingsStore';
import {
  collabAuthApi,
  hasLocalPassword,
  isOidcUser,
  isLocalLoginEnabled,
  performLogout,
  setLogoutCollabTeardown,
  setLogoutEditorReset,
} from './collabAuth';

describe('logout credential revocation', () => {
  afterEach(() => {
    setLogoutCollabTeardown(null);
    setLogoutEditorReset(null);
    vi.restoreAllMocks();
    useSettingsStore.getState().clearCollabAuth();
  });

  it('revokes a refresh token rotated during teardown', async () => {
    useSettingsStore.getState().setCollabAuth({
      accessToken: 'access-before-logout',
      refreshToken: 'refresh-before-logout',
      user: {
        id: 'user-1',
        email: 'writer@example.com',
        displayName: 'Writer',
        emailVerified: true,
      },
    });

    setLogoutCollabTeardown(async () => {
      useSettingsStore.getState().setCollabAuth({
        ...useSettingsStore.getState().collabAuth,
        accessToken: 'rotated-access',
        refreshToken: 'rotated-refresh',
      });
    });
    vi.spyOn(collabAuthApi, 'revokeMyCollabSessions').mockResolvedValue({ message: 'ok' });
    const logout = vi.spyOn(collabAuthApi, 'logout').mockResolvedValue({ message: 'ok' });

    await performLogout();

    expect(logout).toHaveBeenCalledWith('rotated-refresh');
    expect(useSettingsStore.getState().collabAuth.refreshToken).toBeNull();
  });
});

describe('provider-aware account controls', () => {
  const baseUser = {
    id: 'user-1',
    email: 'writer@example.com',
    displayName: 'Writer',
    emailVerified: true,
  };

  it('keeps local controls for legacy and password-linked accounts', () => {
    expect(hasLocalPassword(baseUser)).toBe(true);
    expect(hasLocalPassword({ ...baseUser, authMethods: ['oidc', 'password'] })).toBe(true);
    expect(hasLocalPassword({ ...baseUser, hasPassword: true, authMethods: ['oidc'] })).toBe(true);
  });

  it('recognises an OIDC-only account without treating email as identity', () => {
    const oidcUser = { ...baseUser, hasPassword: false, authMethods: ['oidc'] };
    expect(isOidcUser(oidcUser)).toBe(true);
    expect(hasLocalPassword(oidcUser)).toBe(false);
  });
});

describe('server auth configuration compatibility', () => {
  it('defaults local login on for older servers and honours an explicit disable', () => {
    expect(isLocalLoginEnabled(null)).toBe(true);
    expect(isLocalLoginEnabled({
      localRegistrationEnabled: false,
      googleEnabled: false,
      oidcEnabled: true,
      oidcDisplayName: 'Authentik',
      emailVerificationRequired: false,
    })).toBe(true);
    expect(isLocalLoginEnabled({
      localLoginEnabled: false,
      localRegistrationEnabled: false,
      googleEnabled: false,
      oidcEnabled: true,
      oidcDisplayName: 'Authentik',
      emailVerificationRequired: false,
    })).toBe(false);
  });
});
