import { afterEach, describe, expect, it, vi } from 'vitest';
import { useSettingsStore } from '../stores/settingsStore';
import {
  collabAuthApi,
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
