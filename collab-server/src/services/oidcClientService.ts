import { Issuer, type Client, type IdTokenClaims } from 'openid-client';
import { z } from 'zod';
import type { OidcSettings } from './securityConfig';

export interface VerifiedOidcIdentity {
  issuer: string;
  subject: string;
  email: string;
  displayName: string;
}

const emailSchema = z.string().email().max(255);

function configuredIssuer(settings: OidcSettings): string {
  return settings.issuerUrl;
}

function isLoopback(hostname: string): boolean {
  return hostname === 'localhost'
    || hostname === '127.0.0.1'
    || hostname === '[::1]';
}

export function validateProviderEndpoint(
  name: string,
  value: unknown,
  settings: OidcSettings,
): string {
  if (typeof value !== 'string') throw new Error(`OIDC discovery is missing ${name}`);
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`OIDC discovery returned an invalid ${name}`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`OIDC discovery ${name} must not contain credentials`);
  }
  if (
    parsed.protocol !== 'https:'
    && !(
      parsed.protocol === 'http:'
      && settings.allowHttpLoopback
      && isLoopback(parsed.hostname)
    )
  ) {
    throw new Error(`OIDC discovery ${name} must use HTTPS`);
  }
  return parsed.toString();
}

/**
 * Defense-in-depth validation after openid-client has verified the ID token's
 * signature and standard JWT/OIDC claims against the discovered JWKS.
 */
export function validateOidcClaims(
  claims: IdTokenClaims,
  settings: OidcSettings,
  expectedNonce: string,
  nowSeconds = Math.floor(Date.now() / 1000),
): VerifiedOidcIdentity {
  if (claims.iss !== configuredIssuer(settings)) {
    throw new Error('OIDC issuer mismatch');
  }
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(settings.clientId)) {
    throw new Error('OIDC audience mismatch');
  }
  if (audiences.length > 1 && claims.azp !== settings.clientId) {
    throw new Error('OIDC authorized party mismatch');
  }
  if (claims.azp !== undefined && claims.azp !== settings.clientId) {
    throw new Error('OIDC authorized party mismatch');
  }
  if (!Number.isFinite(claims.exp) || claims.exp <= nowSeconds) {
    throw new Error('OIDC ID token is expired');
  }
  if (claims.nonce !== expectedNonce) {
    throw new Error('OIDC nonce mismatch');
  }
  if (typeof claims.sub !== 'string' || claims.sub.length === 0 || claims.sub.length > 1024) {
    throw new Error('OIDC subject is missing or invalid');
  }
  // Do not treat a provider's mere possession of an address as proof. The
  // provider must explicitly assert the standard boolean verified claim.
  if (claims.email_verified !== true || typeof claims.email !== 'string') {
    throw new Error('OIDC provider did not supply a verified email address');
  }
  const emailResult = emailSchema.safeParse(claims.email.trim().toLowerCase());
  if (!emailResult.success) {
    throw new Error('OIDC provider supplied an invalid email address');
  }

  const candidateName = [claims.name, claims.preferred_username]
    .find((value): value is string => typeof value === 'string' && value.trim().length > 0)
    || emailResult.data.split('@')[0];

  return {
    issuer: claims.iss,
    subject: claims.sub,
    email: emailResult.data,
    displayName: candidateName.trim().slice(0, 100),
  };
}

export class OidcClientService {
  private clientPromise: Promise<Client> | null = null;

  constructor(private readonly settings: OidcSettings) {}

  async authorizationUrl(input: {
    state: string;
    nonce: string;
    codeChallenge: string;
  }): Promise<string> {
    const client = await this.client();
    const authorizationUrl = client.authorizationUrl({
      scope: 'openid profile email',
      response_type: 'code',
      redirect_uri: this.settings.redirectUri,
      state: input.state,
      nonce: input.nonce,
      code_challenge: input.codeChallenge,
      code_challenge_method: 'S256',
    });
    return validateProviderEndpoint('authorization_endpoint', authorizationUrl, this.settings);
  }

  async verifyCallback(input: {
    code: string;
    state: string;
    nonce: string;
    codeVerifier: string;
  }): Promise<VerifiedOidcIdentity> {
    const client = await this.client();
    // `callback` performs discovery-backed JWKS signature validation and
    // validates issuer, audience/azp, expiry, state, nonce, and the code flow.
    const tokenSet = await client.callback(
      this.settings.redirectUri,
      { code: input.code, state: input.state },
      {
        response_type: 'code',
        state: input.state,
        nonce: input.nonce,
        code_verifier: input.codeVerifier,
      },
    );
    if (!tokenSet.id_token) {
      throw new Error('OIDC provider did not return an ID token');
    }
    return validateOidcClaims(tokenSet.claims(), this.settings, input.nonce);
  }

  private async client(): Promise<Client> {
    if (!this.clientPromise) {
      this.clientPromise = this.discover().catch((error) => {
        // Permit a later retry after transient discovery failures.
        this.clientPromise = null;
        throw error;
      });
    }
    return this.clientPromise;
  }

  private async discover(): Promise<Client> {
    const issuer = await Issuer.discover(this.settings.issuerUrl);
    if (issuer.metadata.issuer !== configuredIssuer(this.settings)) {
      throw new Error('OIDC discovery issuer does not match OIDC_ISSUER_URL');
    }
    validateProviderEndpoint(
      'authorization_endpoint',
      issuer.metadata.authorization_endpoint,
      this.settings,
    );
    validateProviderEndpoint('token_endpoint', issuer.metadata.token_endpoint, this.settings);
    validateProviderEndpoint('jwks_uri', issuer.metadata.jwks_uri, this.settings);
    return new issuer.Client({
      client_id: this.settings.clientId,
      client_secret: this.settings.clientSecret,
      redirect_uris: [this.settings.redirectUri],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
    });
  }
}
