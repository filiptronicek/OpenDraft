import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  platformFetch: vi.fn(),
  refresh: vi.fn(),
  state: {
    collabAuth: {
      accessToken: 'local-access-token',
      refreshToken: 'local-refresh-token',
    },
    setCollabAuth: vi.fn(),
    clearCollabAuth: vi.fn(),
  },
}));

vi.mock('./platform', () => ({ platformFetch: mocks.platformFetch }));
vi.mock('./collabAuth', () => ({ collabAuthApi: { refresh: mocks.refresh } }));
vi.mock('../stores/settingsStore', () => ({
  useSettingsStore: { getState: () => mocks.state },
}));

import { authedFetch } from './authedFetch';

function sentAuthorization(call: number): string | null {
  const init = mocks.platformFetch.mock.calls[call][1] as RequestInit;
  return new Headers(init.headers).get('Authorization');
}

describe('authenticated HTTP origin boundary', () => {
  beforeEach(() => {
    localStorage.clear();
    mocks.platformFetch.mockReset();
    mocks.refresh.mockReset();
    mocks.state.setCollabAuth.mockReset();
    mocks.state.clearCollabAuth.mockReset();
  });

  it('strips Authorization and never refreshes a foreign 401', async () => {
    mocks.platformFetch.mockResolvedValueOnce(new Response(null, { status: 401 }));

    const response = await authedFetch('https://evil.example/image.png', {
      headers: { Authorization: 'Bearer caller-supplied-secret' },
    });

    expect(response.status).toBe(401);
    expect(mocks.platformFetch).toHaveBeenCalledTimes(1);
    expect(sentAuthorization(0)).toBeNull();
    expect(mocks.refresh).not.toHaveBeenCalled();
  });

  it('attaches Authorization to the static and live configured API origins', async () => {
    mocks.platformFetch.mockResolvedValue(new Response(null, { status: 200 }));

    await authedFetch('http://localhost/api/projects');
    expect(sentAuthorization(0)).toBe('Bearer local-access-token');

    localStorage.setItem('opendraft:cloudApiUrl', 'https://live-api.example');
    await authedFetch('https://live-api.example/api/projects');
    expect(sentAuthorization(1)).toBe('Bearer local-access-token');
  });

  it('trusts the HTTP form of only the configured collaboration origin', async () => {
    localStorage.setItem('opendraft:collabServerUrl', 'wss://collab.example/collab-server');
    mocks.platformFetch.mockResolvedValue(new Response(null, { status: 200 }));

    await authedFetch('https://collab.example/api/collab/sessions/a/b');
    expect(sentAuthorization(0)).toBe('Bearer local-access-token');

    await authedFetch('https://other-collab.example/api/collab/sessions/a/b');
    expect(sentAuthorization(1)).toBeNull();
  });
});
