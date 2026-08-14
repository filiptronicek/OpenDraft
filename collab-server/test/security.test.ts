import test from 'node:test';
import assert from 'node:assert/strict';
import type { IncomingMessage } from 'http';
import type { Hocuspocus } from '@hocuspocus/server';
import * as jwt from 'jsonwebtoken';

import { config } from '../src/config';
import { generateAccessToken, verifyAccessToken } from '../src/services/tokenService';
import {
  canonicalDocumentName,
  isSessionBoundToDocument,
  parseCanonicalDocumentName,
} from '../src/services/collabValidation';
import { documentPath } from '../src/services/documentPath';
import { inviteSchema } from '../src/routes/collab';
import { closeAndAwaitDocumentUnload } from '../src/services/documentLifecycle';
import { compileTrustedProxy, resolveClientIp } from '../src/services/clientIp';
import { connectionLimitKey, inviteTokenDigest } from '../src/services/connectionIdentity';
import { InviteConnectionRegistry } from '../src/services/inviteConnectionRegistry';
import { applyCollaborationRole } from '../src/services/collaborationAccess';
import { parseSecurityBoolean, registrationSetting } from '../src/services/securityConfig';
import { loginSchema, requiresDeviceForTwoFactor } from '../src/routes/auth';
import { AccountLifecycleGuard } from '../src/services/accountLifecycle';
import { revokeOwnedCollaborationSessions } from '../src/services/collaborationSessionService';
import type { DBAdapter } from '../src/db';
import { deleteUser } from '../src/services/userService';
import { escapeHtml } from '../src/services/emailService';

const validClaims = {
  sub: 'user-1',
  email: 'writer@example.com',
  name: 'Writer',
  email_verified: true,
  type: 'access' as const,
};

test('access tokens carry and enforce the complete JWT contract', () => {
  const token = generateAccessToken(
    validClaims.sub,
    validClaims.email,
    validClaims.name,
    validClaims.email_verified,
  );
  const decoded = jwt.verify(token, config.jwtSecret, {
    algorithms: ['HS256'],
    issuer: config.jwtIssuer,
    audience: config.jwtAudience,
  }) as jwt.JwtPayload;

  assert.equal(decoded.sub, validClaims.sub);
  assert.equal(decoded.email, validClaims.email);
  assert.equal(decoded.name, validClaims.name);
  assert.equal(decoded.email_verified, true);
  assert.equal(decoded.type, 'access');
  assert.match(String(decoded.jti), /^[0-9a-f-]{36}$/i);
  assert.ok(verifyAccessToken(token));

  for (const [issuer, audience] of [
    ['wrong-issuer', config.jwtAudience],
    [config.jwtIssuer, 'wrong-audience'],
  ]) {
    const bad = jwt.sign(validClaims, config.jwtSecret, {
      algorithm: 'HS256',
      issuer,
      audience,
      expiresIn: '1m',
    });
    assert.equal(verifyAccessToken(bad), null);
  }
});

test('an invite is bound to exactly one canonical room', () => {
  const session = {
    project_id: 'project-a',
    script_id: 'script-a',
    session_nonce: 'nonce-a',
  };
  assert.equal(canonicalDocumentName(session), 'project-a/script-a/nonce-a');
  assert.equal(isSessionBoundToDocument(session, 'project-a/script-a/nonce-a'), true);
  assert.equal(isSessionBoundToDocument(session, 'project-a/script-b/nonce-a'), false);
  assert.deepEqual(parseCanonicalDocumentName('project-a/script-a/nonce-a'), {
    projectId: 'project-a',
    scriptId: 'script-a',
    sessionNonce: 'nonce-a',
  });
  assert.equal(parseCanonicalDocumentName('project-a/script-a/nonce-a/extra'), null);
});

test('hashed document paths cannot collide under legacy separator flattening', () => {
  const first = documentPath('/tmp/opendraft-collab-test', 'a/b/c');
  const second = documentPath('/tmp/opendraft-collab-test', 'a--b/c');
  assert.notEqual(first, second);
  assert.match(first, /[a-f0-9]{64}\.yjs$/);
  assert.match(second, /[a-f0-9]{64}\.yjs$/);
});

test('invite validation rejects unsafe identifiers and strips client nonces', () => {
  const valid = inviteSchema.safeParse({
    project_id: 'project',
    script_id: 'script',
    collaborator_name: 'Guest',
    role: 'viewer',
    expires_in_hours: 1,
    session_nonce: 'attacker-selected',
  });
  assert.equal(valid.success, true);
  if (valid.success) assert.equal('session_nonce' in valid.data, false);

  for (const candidate of [
    { project_id: '../project' },
    { script_id: 'script/other' },
    { role: 'owner' },
    { expires_in_hours: 0.1 },
  ]) {
    const parsed = inviteSchema.safeParse({
      project_id: 'project',
      script_id: 'script',
      collaborator_name: 'Guest',
      role: 'editor',
      expires_in_hours: 1,
      ...candidate,
    });
    assert.equal(parsed.success, false);
  }
});

test('viewer invites map to protocol-level read-only access', () => {
  const viewer = { readOnly: false };
  assert.equal(applyCollaborationRole(viewer, 'viewer'), 'viewer');
  assert.equal(viewer.readOnly, true);
  const editor = { readOnly: true };
  assert.equal(applyCollaborationRole(editor, 'editor'), 'editor');
  assert.equal(editor.readOnly, false);
  assert.throws(() => applyCollaborationRole({ readOnly: false }, 'owner'));
});

test('security-sensitive registration switches reject typos', () => {
  assert.equal(parseSecurityBoolean('FLAG', 'true', false), true);
  assert.equal(parseSecurityBoolean('FLAG', 'OFF', true), false);
  assert.equal(registrationSetting({
    LOCAL_LOGIN_ENABLED: 'false',
    LOCAL_REGISTRATION_ENABLED: 'true',
  }), false);
  assert.throws(
    () => registrationSetting({ LOCAL_REGISTRATION_ENABLED: 'flase' }),
    /LOCAL_REGISTRATION_ENABLED/,
  );
  assert.throws(
    () => registrationSetting({ REGISTRATION_ENABLED: 'maybe' }),
    /REGISTRATION_ENABLED/,
  );
});

test('2FA accounts cannot omit or malform device context', () => {
  const omitted = loginSchema.safeParse({
    email: 'writer@example.com', password: 'Password9',
  });
  assert.equal(omitted.success, true);
  assert.equal(requiresDeviceForTwoFactor(1, null), true);
  assert.equal(requiresDeviceForTwoFactor(0, null), false);
  const malformed = loginSchema.safeParse({
    email: 'writer@example.com',
    password: 'Password9',
    device: { deviceId: 'short', deviceName: '' },
  });
  assert.equal(malformed.success, false);
});

function fakeDocument() {
  return {
    saveMutex: { isLocked: () => false },
    getConnectionsCount: () => 0,
  };
}

test('document close waits for in-flight loads before reporting unload', async () => {
  const documentName = 'project/script/nonce';
  const documents = new Map<string, any>();
  const loadingDocuments = new Map<string, Promise<any>>();
  const loading = new Promise<void>((resolve) => {
    setTimeout(() => {
      loadingDocuments.delete(documentName);
      documents.set(documentName, fakeDocument());
      resolve();
    }, 5);
  });
  loadingDocuments.set(documentName, loading);

  const server = {
    documents,
    loadingDocuments,
    closeConnections: () => undefined,
    debouncer: {
      isDebounced: () => false,
      isCurrentlyExecuting: () => false,
      executeNow: () => undefined,
    },
    unloadDocument: async () => { documents.delete(documentName); },
  } as unknown as Hocuspocus;

  assert.equal(await closeAndAwaitDocumentUnload(server, documentName, 100, 1), true);
  assert.equal(documents.has(documentName), false);
  assert.equal(loadingDocuments.has(documentName), false);
});

test('document close fails closed when a load never settles', async () => {
  const documentName = 'project/script/nonce';
  const never = new Promise(() => undefined);
  const server = {
    documents: new Map(),
    loadingDocuments: new Map([[documentName, never]]),
    closeConnections: () => undefined,
    debouncer: {
      isDebounced: () => false,
      isCurrentlyExecuting: () => false,
      executeNow: () => undefined,
    },
    unloadDocument: async () => undefined,
  } as unknown as Hocuspocus;
  assert.equal(await closeAndAwaitDocumentUnload(server, documentName, 8, 1), false);
});

test('forwarded client IPs are accepted only from trusted direct peers', () => {
  const trust = compileTrustedProxy(['loopback']);
  const trustedRequest = {
    socket: { remoteAddress: '127.0.0.1' },
    headers: { 'x-forwarded-for': '198.51.100.8' },
  } as unknown as IncomingMessage;
  assert.equal(resolveClientIp(trustedRequest, trust), '198.51.100.8');

  const directRequest = {
    socket: { remoteAddress: '203.0.113.7' },
    headers: { 'x-forwarded-for': '198.51.100.8' },
  } as unknown as IncomingMessage;
  assert.equal(resolveClientIp(directRequest, trust), '203.0.113.7');
});

test('guest limits and live registry keys never retain raw invite tokens', () => {
  const token = 'high-entropy-invite-token-value';
  const digest = inviteTokenDigest(token);
  assert.equal(connectionLimitKey('user-1', token), 'user:user-1');
  assert.equal(connectionLimitKey(null, token), 'invite:' + digest);
  assert.equal(connectionLimitKey(null, token).includes(token), false);

  const closes: Array<{ code?: number; reason?: string }> = [];
  const registry = new InviteConnectionRegistry();
  const connection = {
    webSocket: {
      close: (code?: number, reason?: string) => closes.push({ code, reason }),
    },
  };
  const expiresAt = new Date(Date.now() + 60_000).toISOString();
  registry.register('socket-1', connection, digest, expiresAt);
  assert.equal(registry.closeToken(token, expiresAt), 1);
  assert.deepEqual(closes[0], { code: 4403, reason: 'Invite revoked or expired' });

  registry.unregister('socket-1');
  assert.equal(registry.register('socket-late', connection, digest, expiresAt), false);
  assert.equal(closes.length, 2);

  const otherDigest = inviteTokenDigest('other-high-entropy-token');
  const otherExpiry = Date.now() + 60_000;
  assert.equal(
    registry.register('socket-2', connection, otherDigest, new Date(otherExpiry).toISOString()),
    true,
  );
  assert.equal(registry.closeExpired(otherExpiry + 1), 1);
  assert.equal(closes.length, 3);
});

test('account invite cleanup closes every owned socket and tombstones late registrations', () => {
  const registry = new InviteConnectionRegistry();
  const closes: string[] = [];
  const connectionFor = (name: string) => ({
    webSocket: { close: () => closes.push(name) },
  });
  const expiresAt = new Date(Date.now() + 60_000).toISOString();
  const sessions = [
    { token: 'owned-invite-token-one', expires_at: expiresAt },
    { token: 'owned-invite-token-two', expires_at: expiresAt },
  ];
  registry.register(
    'owned-1', connectionFor('one'), inviteTokenDigest(sessions[0].token), expiresAt,
  );
  registry.register(
    'owned-2', connectionFor('two'), inviteTokenDigest(sessions[1].token), expiresAt,
  );

  assert.equal(registry.closeSessions(sessions), 2);
  assert.deepEqual(closes.sort(), ['one', 'two']);
  assert.equal(
    registry.register(
      'late-owned', connectionFor('late'), inviteTokenDigest(sessions[0].token), expiresAt,
    ),
    false,
  );
  assert.equal(closes.includes('late'), true);
});

test('account deletion waits for an in-flight invite and rejects later creates', async () => {
  const guard = new AccountLifecycleGuard();
  const events: string[] = [];
  let releaseCreate!: () => void;
  const createCanFinish = new Promise<void>((resolve) => { releaseCreate = resolve; });
  let markCreateStarted!: () => void;
  const createStarted = new Promise<void>((resolve) => { markCreateStarted = resolve; });

  const creation = guard.runActive('user-1', async () => {
    events.push('create-start');
    markCreateStarted();
    await createCanFinish;
    events.push('create-end');
    return 'invite';
  });
  await createStarted;

  const deletion = guard.runDeletion('user-1', async () => {
    events.push('delete');
  });
  await Promise.resolve();
  assert.deepEqual(events, ['create-start']);

  releaseCreate();
  assert.deepEqual(await creation, { accepted: true, value: 'invite' });
  assert.deepEqual(await deletion, { accepted: true, value: undefined });
  assert.deepEqual(events, ['create-start', 'create-end', 'delete']);

  let laterCreateRan = false;
  assert.deepEqual(
    await guard.runActive('user-1', async () => { laterCreateRan = true; }),
    { accepted: false },
  );
  assert.equal(laterCreateRan, false);
});

test('password security events deactivate owned invites and close live sockets', async () => {
  const expiresAt = new Date(Date.now() + 60_000).toISOString();
  const sessions = [
    { token: 'security-event-invite-one', expires_at: expiresAt },
    { token: 'security-event-invite-two', expires_at: expiresAt },
  ];
  const updates: Array<{ sql: string; params?: unknown[] }> = [];
  const db = {
    all: async () => sessions,
    run: async (sql: string, params?: unknown[]) => {
      updates.push({ sql, params });
      return { changes: 2 };
    },
  } as unknown as DBAdapter;
  const registry = new InviteConnectionRegistry();
  const closed: string[] = [];
  for (const [index, session] of sessions.entries()) {
    registry.register(
      `security-socket-${index}`,
      { webSocket: { close: () => closed.push(session.token) } },
      inviteTokenDigest(session.token),
      expiresAt,
    );
  }

  const result = await revokeOwnedCollaborationSessions('user-1', db, registry);
  assert.deepEqual(result, { revoked: 2, closed: 2 });
  assert.equal(updates.length, 1);
  assert.match(updates[0].sql, /UPDATE collab_sessions SET active = 0/);
  assert.deepEqual(updates[0].params, ['user-1']);
  assert.deepEqual(closed.sort(), sessions.map((session) => session.token).sort());
  assert.equal(
    registry.register(
      'late-security-socket',
      { webSocket: { close: () => closed.push('late') } },
      inviteTokenDigest(sessions[0].token),
      expiresAt,
    ),
    false,
  );
  assert.equal(closed.includes('late'), true);
});

test('account deletion removes owned invite credentials after deleting the owner', async () => {
  let sessions = [
    { token: 'owned-before-delete', createdBy: 'user-1' },
    { token: 'other-user-invite', createdBy: 'user-2' },
  ];
  const statements: string[] = [];
  const db = {
    run: async (sql: string) => {
      statements.push(sql);
      if (sql.startsWith('DELETE FROM collab_sessions')) {
        sessions = sessions.filter((session) => session.createdBy !== 'user-1');
      }
      return { changes: 1 };
    },
  } as unknown as DBAdapter;

  await deleteUser('user-1', db);

  assert.deepEqual(sessions, [
    { token: 'other-user-invite', createdBy: 'user-2' },
  ]);
  const ownerDelete = statements.indexOf('DELETE FROM users WHERE id = ?');
  const inviteDeletes = statements
    .map((sql, index) => ({ sql, index }))
    .filter(({ sql }) => sql.startsWith('DELETE FROM collab_sessions'));
  assert.equal(inviteDeletes.length, 2);
  assert.ok(ownerDelete >= 0);
  assert.ok(inviteDeletes[1].index > ownerDelete);
});

test('deletion failures retry before owner removal and fail closed after uncertainty', async () => {
  const guard = new AccountLifecycleGuard();

  await assert.rejects(
    guard.runDeletion('retryable-user', async () => {
      throw new Error('pre-delete cleanup failed');
    }),
    /pre-delete cleanup failed/,
  );
  assert.deepEqual(
    await guard.runDeletion('retryable-user', async () => 'deleted'),
    { accepted: true, value: 'deleted' },
  );

  await assert.rejects(
    guard.runDeletion('uncertain-user', async (markDeletion) => {
      markDeletion();
      throw new Error('owner delete outcome unknown');
    }),
    /owner delete outcome unknown/,
  );
  let activeWorkRan = false;
  assert.deepEqual(
    await guard.runActive('uncertain-user', async () => { activeWorkRan = true; }),
    { accepted: false },
  );
  assert.equal(activeWorkRan, false);
});

test('security email HTML escapes every metacharacter', () => {
  assert.equal(escapeHtml('&<>"'), '&amp;&lt;&gt;&quot;');
  assert.equal(escapeHtml(String.fromCharCode(39)), '&#39;');
});
