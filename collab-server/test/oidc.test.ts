import test from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'node:http';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { exportJWK, generateKeyPair, SignJWT, type KeyLike } from 'jose';
import type { IdTokenClaims } from 'openid-client';

import {
  appUrlSetting,
  localLoginSetting,
  oidcSetting,
  type OidcSettings,
} from '../src/services/securityConfig';
import {
  OIDC_COOKIE_PATH,
  OIDC_TRANSACTION_COOKIE,
  OidcStateStore,
  oidcTransactionCookie,
  parseCookie,
  pkceChallenge,
  safeReturnTo,
} from '../src/services/oidcStateService';
import {
  OidcClientService,
  validateOidcClaims,
  validateProviderEndpoint,
} from '../src/services/oidcClientService';
import { SQLiteAdapter } from '../src/database/sqlite';
import {
  ExternalIdentityAlreadyLinkedError,
  ExternalIdentityEmailConflictError,
  ExternalIdentityEmailMismatchError,
  findOrCreateExternalUser,
  findOrCreateGoogleUser,
  linkExternalIdentity,
} from '../src/services/userService';

const productionOidcEnv = {
  NODE_ENV: 'production',
  OIDC_ISSUER_URL: 'https://auth.example.test/application/o/opendraft/',
  OIDC_CLIENT_ID: 'opendraft',
  OIDC_CLIENT_SECRET: 'super-secret',
  OIDC_REDIRECT_URI: 'https://scripts.example.test/api/auth/oidc/callback',
};

test('OIDC configuration is disabled when absent and rejects every partial combination', () => {
  assert.equal(oidcSetting({}), null);
  assert.throws(
    () => oidcSetting({ OIDC_DISPLAY_NAME: 'Authentik' }),
    /Incomplete OIDC configuration/,
  );
  for (const missing of [
    'OIDC_ISSUER_URL',
    'OIDC_CLIENT_ID',
    'OIDC_CLIENT_SECRET',
    'OIDC_REDIRECT_URI',
  ]) {
    const environment = { ...productionOidcEnv };
    delete environment[missing as keyof typeof environment];
    assert.throws(() => oidcSetting(environment), /Incomplete OIDC configuration/);
  }
  assert.throws(
    () => oidcSetting({
      ...productionOidcEnv,
      OIDC_CLIENT_SECRET_FILE: '/run/secrets/oidc',
    }),
    /only one/,
  );
});

test('OIDC configuration loads mounted secrets and validates URLs and display text', () => {
  const fromFile: NodeJS.ProcessEnv = { ...productionOidcEnv };
  delete fromFile.OIDC_CLIENT_SECRET;
  const settings = oidcSetting(
    {
      ...fromFile,
      OIDC_CLIENT_SECRET_FILE: '/run/secrets/oidc',
      OIDC_DISPLAY_NAME: 'Authentik',
    },
    (filePath) => {
      assert.equal(filePath, '/run/secrets/oidc');
      return ' file-secret\n';
    },
  );
  assert.equal(settings?.clientSecret, 'file-secret');
  assert.equal(settings?.displayName, 'Authentik');
  assert.equal(settings?.allowHttpLoopback, false);

  assert.throws(
    () => oidcSetting({ ...productionOidcEnv, OIDC_ISSUER_URL: 'http://auth.example.test/' }),
    /must use HTTPS/,
  );
  assert.throws(
    () => oidcSetting({
      ...productionOidcEnv,
      OIDC_REDIRECT_URI: 'http://localhost:3000/api/auth/oidc/callback',
    }),
    /must use HTTPS/,
  );
  assert.doesNotThrow(() => oidcSetting({
    ...productionOidcEnv,
    NODE_ENV: 'test',
    OIDC_ISSUER_URL: 'http://127.0.0.1:9000/',
    OIDC_REDIRECT_URI: 'http://localhost:3000/api/auth/oidc/callback',
  }));
  assert.throws(
    () => oidcSetting({
      ...productionOidcEnv,
      NODE_ENV: 'test',
      OIDC_ISSUER_URL: 'http://auth.example.test/',
    }),
    /local development/,
  );
  assert.throws(
    () => oidcSetting({ ...productionOidcEnv, OIDC_DISPLAY_NAME: 'Bad\nName' }),
    /OIDC_DISPLAY_NAME/,
  );
});

test('APP_URL is a fixed secure origin and local login parsing fails closed', () => {
  assert.equal(
    appUrlSetting({ NODE_ENV: 'production', APP_URL: 'https://scripts.example.test/' }, true),
    'https://scripts.example.test',
  );
  assert.throws(
    () => appUrlSetting(
      { NODE_ENV: 'production', APP_URL: 'http://scripts.example.test' },
      true,
    ),
    /must use HTTPS/,
  );
  assert.throws(
    () => appUrlSetting({ APP_URL: 'https://scripts.example.test/base' }, true),
    /must be an origin/,
  );
  assert.throws(
    () => appUrlSetting({ NODE_ENV: 'production' }, true),
    /explicitly configured/,
  );
  assert.equal(appUrlSetting({ NODE_ENV: 'production' }), 'http://localhost:5173');
  assert.equal(localLoginSetting({ LOCAL_LOGIN_ENABLED: 'false' }), false);
  assert.throws(() => localLoginSetting({ LOCAL_LOGIN_ENABLED: 'flase' }), /LOCAL_LOGIN_ENABLED/);
});

test('OIDC transaction uses PKCE and a secure browser-binding cookie', () => {
  const store = new OidcStateStore(5_000, 1_000);
  const transaction = store.createTransaction('/projects?tab=recent', null, 1_000);
  assert.equal(transaction.codeChallenge, pkceChallenge(transaction.codeVerifier));
  assert.match(transaction.codeVerifier, /^[A-Za-z0-9_-]{43,128}$/);
  assert.notEqual(transaction.state, transaction.nonce);

  const cookie = oidcTransactionCookie(transaction.cookieValue, 300);
  assert.match(cookie, new RegExp(`^${OIDC_TRANSACTION_COOKIE}=`));
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /Secure/);
  assert.match(cookie, /SameSite=Lax/);
  assert.match(cookie, new RegExp(`Path=${OIDC_COOKIE_PATH}`));
  assert.equal(
    parseCookie(`unrelated=x; ${OIDC_TRANSACTION_COOKIE}=${transaction.cookieValue}`, OIDC_TRANSACTION_COOKIE),
    transaction.cookieValue,
  );

  const consumed = store.consumeTransaction(
    transaction.state,
    transaction.cookieValue,
    2_000,
  );
  assert.equal(consumed?.returnTo, '/projects?tab=recent');
  assert.equal(store.consumeTransaction(transaction.state, transaction.cookieValue, 2_001), null);
});

test('OIDC state binding, expiry, handoff, and redirect targets are one-use and fail closed', () => {
  const store = new OidcStateStore(100, 50);
  const wrongBinding = store.createTransaction('/', null, 1_000);
  assert.equal(store.consumeTransaction(wrongBinding.state, 'wrong-cookie', 1_001), null);
  assert.equal(
    store.consumeTransaction(wrongBinding.state, wrongBinding.cookieValue, 1_002),
    null,
  );
  const expired = store.createTransaction('/', null, 2_000);
  assert.equal(store.consumeTransaction(expired.state, expired.cookieValue, 2_100), null);

  const handoff = store.createHandoff('user-1', '/project/one', 3_000);
  assert.deepEqual(store.consumeHandoff(handoff.code, handoff.cookieValue, 3_049), {
    userId: 'user-1',
    returnTo: '/project/one',
  });
  assert.equal(store.consumeHandoff(handoff.code, handoff.cookieValue, 3_049), null);
  const stolen = store.createHandoff('user-1', '/', 3_100);
  assert.equal(store.consumeHandoff(stolen.code, null, 3_101), null);
  assert.equal(store.consumeHandoff(stolen.code, stolen.cookieValue, 3_102), null);
  const expiredCode = store.createHandoff('user-1', '/', 4_000);
  assert.equal(store.consumeHandoff(expiredCode.code, expiredCode.cookieValue, 4_050), null);

  assert.equal(safeReturnTo('https://evil.example/steal'), '/');
  assert.equal(safeReturnTo('//evil.example/steal'), '/');
  assert.equal(safeReturnTo('/auth/oidc/callback?code=stale'), '/');
  assert.equal(safeReturnTo('/projects/one?tab=script#scene'), '/projects/one?tab=script#scene');
});

const claimSettings: OidcSettings = {
  issuerUrl: 'https://auth.example.test/application/o/opendraft/',
  clientId: 'opendraft',
  clientSecret: 'secret',
  redirectUri: 'https://scripts.example.test/api/auth/oidc/callback',
  displayName: 'Authentik',
  allowHttpLoopback: false,
};

function claims(overrides: Partial<IdTokenClaims> = {}): IdTokenClaims {
  return {
    iss: claimSettings.issuerUrl,
    aud: claimSettings.clientId,
    sub: 'authentik-user-1',
    exp: 2_000,
    iat: 1_000,
    nonce: 'expected-nonce',
    email: 'Writer@Example.com',
    email_verified: true,
    ...overrides,
  };
}

test('OIDC claims require exact issuer, audience, nonce, expiry, and verified email', () => {
  assert.deepEqual(
    validateOidcClaims(claims(), claimSettings, 'expected-nonce', 1_500),
    {
      issuer: claimSettings.issuerUrl,
      subject: 'authentik-user-1',
      email: 'writer@example.com',
      displayName: 'writer',
    },
  );
  for (const invalid of [
    claims({ iss: 'https://other.example.test/' }),
    claims({ aud: 'another-client' }),
    claims({ aud: ['opendraft', 'another-client'], azp: 'another-client' }),
    claims({ nonce: 'other-nonce' }),
    claims({ exp: 1_500 }),
    claims({ email_verified: false }),
    claims({ email_verified: 'true' as unknown as boolean }),
  ]) {
    assert.throws(
      () => validateOidcClaims(invalid, claimSettings, 'expected-nonce', 1_500),
    );
  }
});

test('discovered provider endpoints cannot downgrade or leave the configured trust boundary', () => {
  assert.equal(
    validateProviderEndpoint(
      'authorization_endpoint',
      'https://auth.example.test/application/o/authorize/?x=1',
      claimSettings,
    ),
    'https://auth.example.test/application/o/authorize/?x=1',
  );
  assert.throws(
    () => validateProviderEndpoint(
      'authorization_endpoint',
      'http://auth.example.test/authorize',
      claimSettings,
    ),
    /must use HTTPS/,
  );
  assert.throws(
    () => validateProviderEndpoint(
      'authorization_endpoint',
      'https://user:password@auth.example.test/authorize',
      claimSettings,
    ),
    /credentials/,
  );
});

const identitySchema = `
  CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    email_verified INTEGER DEFAULT 0,
    password_hash TEXT,
    google_id TEXT UNIQUE,
    display_name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    two_factor_enabled INTEGER DEFAULT 0
  );
  CREATE TABLE external_identities (
    id TEXT PRIMARY KEY,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (issuer, subject)
  );
`;

test('external identities never auto-link email and explicit links cannot be stolen', async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opendraft-oidc-test-'));
  const db = new SQLiteAdapter(dataDir);
  t.after(async () => {
    await db.close();
    fs.rmSync(dataDir, { recursive: true, force: true });
  });
  await db.exec(identitySchema);
  await db.exec(`
    CREATE TRIGGER reject_test_identity
    BEFORE INSERT ON external_identities
    WHEN NEW.subject = 'force-rollback'
    BEGIN
      SELECT RAISE(ABORT, 'forced identity insert failure');
    END;
  `);
  const now = new Date().toISOString();
  await db.run(
    `INSERT INTO users
      (id, email, email_verified, password_hash, display_name, created_at, updated_at)
     VALUES (?, ?, 0, ?, ?, ?, ?)`,
    ['local-1', 'writer@example.com', 'password-hash', 'Writer', now, now],
  );
  await db.run(
    `INSERT INTO users
      (id, email, email_verified, password_hash, display_name, created_at, updated_at)
     VALUES (?, ?, 1, ?, ?, ?, ?)`,
    ['local-2', 'other@example.com', 'password-hash', 'Other', now, now],
  );

  await assert.rejects(findOrCreateExternalUser({
    issuer: claimSettings.issuerUrl,
    subject: 'force-rollback',
    email: 'rollback@example.com',
    displayName: 'Rollback',
  }, db), /forced identity insert failure/);
  assert.equal(
    await db.get('SELECT id FROM users WHERE email = ?', ['rollback@example.com']),
    undefined,
  );

  const identity = {
    issuer: claimSettings.issuerUrl,
    subject: 'subject-1',
    email: 'writer@example.com',
    displayName: 'OIDC Writer',
  };
  await assert.rejects(
    findOrCreateExternalUser(identity, db),
    ExternalIdentityEmailConflictError,
  );
  assert.equal(
    (await db.get<{ count: number }>('SELECT COUNT(*) AS count FROM external_identities'))?.count,
    0,
  );

  const linked = await linkExternalIdentity('local-1', identity, db);
  assert.equal(linked.id, 'local-1');
  assert.equal(linked.email_verified, 1);
  assert.equal(Number(linked.external_identity_count), 1);
  await assert.rejects(
    linkExternalIdentity('local-2', identity, db),
    ExternalIdentityAlreadyLinkedError,
  );
  await assert.rejects(
    linkExternalIdentity(
      'local-2',
      { ...identity, subject: 'unclaimed-subject' },
      db,
    ),
    ExternalIdentityEmailMismatchError,
  );
  const resolved = await findOrCreateExternalUser(
    { ...identity, email: 'renamed@example.com' },
    db,
  );
  assert.equal(resolved.id, 'local-1');
  assert.equal(resolved.email, 'writer@example.com');

  const provisioned = await findOrCreateExternalUser({
    ...identity,
    subject: 'subject-2',
    email: 'new-user@example.com',
  }, db);
  assert.equal(provisioned.password_hash, null);
  assert.equal(provisioned.email_verified, 1);
  assert.equal(Number(provisioned.external_identity_count), 1);
  await assert.rejects(
    findOrCreateGoogleUser(
      'google-subject',
      'new-user@example.com',
      'Google user',
      db,
    ),
    ExternalIdentityEmailConflictError,
  );
  const afterGoogle = await db.get<{ google_id: string | null }>(
    'SELECT google_id FROM users WHERE id = ?',
    [provisioned.id],
  );
  assert.equal(afterGoogle?.google_id, null);

  await db.run(
    `INSERT INTO users
      (id, email, email_verified, password_hash, display_name, created_at, updated_at)
     VALUES (?, ?, 1, NULL, ?, ?, ?)`,
    ['passwordless-gap', 'gap@example.com', 'Gap', now, now],
  );
  await assert.rejects(
    findOrCreateGoogleUser('google-gap', 'gap@example.com', 'Google gap', db),
    ExternalIdentityEmailConflictError,
  );
});

interface MockProvider {
  issuer: string;
  close: () => Promise<void>;
  privateKey: KeyLike;
  wrongPrivateKey: KeyLike;
  tokenRequests: URLSearchParams[];
}

async function startMockProvider(expectedNonce: string): Promise<MockProvider> {
  const signing = await generateKeyPair('RS256');
  const wrongSigning = await generateKeyPair('RS256');
  const publicJwk = await exportJWK(signing.publicKey);
  Object.assign(publicJwk, { kid: 'provider-key', alg: 'RS256', use: 'sig' });
  const tokenRequests: URLSearchParams[] = [];
  let issuer = '';

  const server = http.createServer((request, response) => {
    void (async () => {
      if (request.url === '/.well-known/openid-configuration') {
        response.setHeader('Content-Type', 'application/json');
        response.end(JSON.stringify({
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/token`,
          jwks_uri: `${issuer}/jwks`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256'],
          token_endpoint_auth_methods_supported: ['client_secret_basic'],
        }));
        return;
      }
      if (request.url === '/jwks') {
        response.setHeader('Content-Type', 'application/json');
        response.end(JSON.stringify({ keys: [publicJwk] }));
        return;
      }
      if (request.url === '/token' && request.method === 'POST') {
        let body = '';
        for await (const chunk of request) body += chunk;
        const parameters = new URLSearchParams(body);
        tokenRequests.push(parameters);
        const code = parameters.get('code') || 'valid';
        const now = Math.floor(Date.now() / 1000);
        const payload: Record<string, unknown> = {
          nonce: expectedNonce,
          email: 'writer@example.com',
          email_verified: true,
          name: 'Writer',
        };
        let tokenIssuer = issuer;
        let audience: string | string[] = 'test-client';
        let expiresAt = now + 60;
        let signingKey = signing.privateKey;
        if (code === 'wrong-issuer') tokenIssuer = `${issuer}/other`;
        if (code === 'wrong-audience') audience = 'other-client';
        if (code === 'expired') expiresAt = now - 1;
        if (code === 'wrong-nonce') payload.nonce = 'wrong-nonce';
        if (code === 'unverified-email') payload.email_verified = false;
        if (code === 'bad-signature') signingKey = wrongSigning.privateKey;
        const idToken = await new SignJWT(payload)
          .setProtectedHeader({ alg: 'RS256', kid: 'provider-key', typ: 'JWT' })
          .setIssuer(tokenIssuer)
          .setAudience(audience)
          .setSubject('provider-subject')
          .setIssuedAt(now)
          .setExpirationTime(expiresAt)
          .sign(signingKey);
        response.setHeader('Content-Type', 'application/json');
        response.end(JSON.stringify({
          access_token: 'provider-access-token',
          token_type: 'Bearer',
          id_token: idToken,
        }));
        return;
      }
      response.statusCode = 404;
      response.end();
    })().catch(() => {
      response.statusCode = 500;
      response.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('mock provider did not bind');
  issuer = `http://127.0.0.1:${address.port}`;
  return {
    issuer,
    privateKey: signing.privateKey,
    wrongPrivateKey: wrongSigning.privateKey,
    tokenRequests,
    close: () => new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    }),
  };
}

test('OIDC client performs discovery, S256 PKCE, and strict signed-token validation', async (t) => {
  const expectedNonce = 'expected-provider-nonce';
  const provider = await startMockProvider(expectedNonce);
  t.after(provider.close);
  const settings: OidcSettings = {
    issuerUrl: provider.issuer,
    clientId: 'test-client',
    clientSecret: 'test-secret',
    redirectUri: 'http://localhost:3000/api/auth/oidc/callback',
    displayName: 'Mock provider',
    allowHttpLoopback: true,
  };
  const service = new OidcClientService(settings);
  const authorizationUrl = new URL(await service.authorizationUrl({
    state: 'test-state',
    nonce: expectedNonce,
    codeChallenge: 'test-code-challenge',
  }));
  assert.equal(authorizationUrl.origin, provider.issuer);
  assert.equal(authorizationUrl.searchParams.get('response_type'), 'code');
  assert.equal(authorizationUrl.searchParams.get('code_challenge'), 'test-code-challenge');
  assert.equal(authorizationUrl.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(authorizationUrl.searchParams.get('nonce'), expectedNonce);

  const verify = (code: string) => service.verifyCallback({
    code,
    state: `state-${code}`,
    nonce: expectedNonce,
    codeVerifier: `verifier-${code}-abcdefghijklmnopqrstuvwxyz0123456789`,
  });
  assert.deepEqual(await verify('valid'), {
    issuer: provider.issuer,
    subject: 'provider-subject',
    email: 'writer@example.com',
    displayName: 'Writer',
  });
  assert.match(provider.tokenRequests[0].get('code_verifier') || '', /^verifier-valid-/);

  for (const code of [
    'wrong-issuer',
    'wrong-audience',
    'expired',
    'wrong-nonce',
    'unverified-email',
    'bad-signature',
  ]) {
    await assert.rejects(verify(code), `${code} must be rejected`);
  }
});
