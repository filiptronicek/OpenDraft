import { describe, expect, it } from 'vitest';
import {
  buildCollabInviteUrl,
  buildCollabProviderToken,
  isTrustedCollabTransport,
  parseCollabInvite,
  readCollabRouteToken,
} from './collabInvite';

const token = 'abcdefghijklmnopqrstuvwxyz012345';

describe('collaboration invite URLs', () => {
  it('uses configured transport for a same-origin SPA link', () => {
    expect(parseCollabInvite(
      `https://drafts.example/collab#${token}`,
      {
        configuredCollabUrl: 'wss://drafts.example/collab-server',
        frontendBaseUrls: ['https://drafts.example', 'https://drafts.example/api'],
      },
    )).toEqual({
      token,
      collabServerUrl: 'wss://drafts.example/collab-server',
    });
  });

  it('keeps legacy direct-collab host links compatible', () => {
    expect(parseCollabInvite(
      `https://collab.legacy.example/collab/${token}`,
      {
        configuredCollabUrl: 'wss://drafts.example/collab-server',
        frontendBaseUrls: ['https://drafts.example'],
      },
    )).toEqual({
      token,
      collabServerUrl: 'wss://collab.legacy.example',
    });
  });

  it('builds public SPA fragment links for web and Tauri', () => {
    expect(buildCollabInviteUrl(token, {
      isTauri: false,
      browserOrigin: 'https://drafts.example',
      apiBase: 'https://ignored.example/api',
    })).toBe(`https://drafts.example/collab#${token}`);

    expect(buildCollabInviteUrl(token, {
      isTauri: true,
      browserOrigin: 'tauri://localhost',
      apiBase: 'https://nas.example/api',
    })).toBe(`https://nas.example/collab#${token}`);
  });

  it('reads fragment routes and preserves legacy path params', () => {
    expect(readCollabRouteToken(undefined, '/collab', `#${token}`)).toBe(token);
    expect(readCollabRouteToken(token, `/collab/${token}`, '')).toBe(token);
    expect(readCollabRouteToken(undefined, '/collab', '#not valid')).toBeUndefined();
  });
});

describe('collaboration transport credentials', () => {
  const payload = Buffer.from(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 60 }))
    .toString('base64url');
  const accessToken = 'header.' + payload + '.signature';

  it('never sends the local account JWT to a foreign invite origin', () => {
    expect(isTrustedCollabTransport(
      'wss://attacker.example', 'wss://trusted.example/collab-server',
    )).toBe(false);
    expect(buildCollabProviderToken(
      token, accessToken, 'wss://attacker.example', 'wss://trusted.example/collab-server',
    )).toBe(token);
  });

  it('adds a live account JWT only for the configured collab origin', () => {
    expect(buildCollabProviderToken(
      token, accessToken, 'wss://trusted.example/legacy', 'wss://trusted.example/collab-server',
    )).toBe('jwt:' + accessToken + '|invite:' + token);
  });
});
