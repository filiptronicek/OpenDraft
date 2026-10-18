import * as fs from 'fs';

const TRUE_VALUES = new Set(['1', 'true', 'yes', 'on']);
const FALSE_VALUES = new Set(['0', 'false', 'no', 'off']);

export interface OidcSettings {
  issuerUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  displayName: string;
  allowHttpLoopback: boolean;
}

/** Parse security-sensitive feature switches without treating typos as true. */
export function parseSecurityBoolean(
  name: string,
  value: string | undefined,
  defaultValue: boolean,
): boolean {
  if (value === undefined) return defaultValue;
  const normalized = value.trim().toLowerCase();
  if (TRUE_VALUES.has(normalized)) return true;
  if (FALSE_VALUES.has(normalized)) return false;
  throw new Error(
    `${name} must be one of: true, false, 1, 0, yes, no, on, off`,
  );
}

export function registrationSetting(environment: NodeJS.ProcessEnv): boolean {
  if (!localLoginSetting(environment)) return false;
  if (environment.LOCAL_REGISTRATION_ENABLED !== undefined) {
    return parseSecurityBoolean('LOCAL_REGISTRATION_ENABLED', environment.LOCAL_REGISTRATION_ENABLED, true);
  }
  return parseSecurityBoolean('REGISTRATION_ENABLED', environment.REGISTRATION_ENABLED, true);
}

export function localLoginSetting(environment: NodeJS.ProcessEnv): boolean {
  return parseSecurityBoolean('LOCAL_LOGIN_ENABLED', environment.LOCAL_LOGIN_ENABLED, true);
}

function nonEmpty(environment: NodeJS.ProcessEnv, name: string): string | undefined {
  const value = environment[name]?.trim();
  return value || undefined;
}

function isLoopback(hostname: string): boolean {
  return hostname === 'localhost'
    || hostname === '127.0.0.1'
    || hostname === '[::1]';
}

function absoluteHttpUrl(
  name: string,
  value: string,
  environment: NodeJS.ProcessEnv,
  allowAnyHttp = false,
): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute HTTP(S) URL`);
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error(`${name} must be an absolute HTTP(S) URL`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`${name} must not contain URL credentials`);
  }
  if (
    parsed.protocol === 'http:'
    && !allowAnyHttp
    && (environment.NODE_ENV === 'production' || !isLoopback(parsed.hostname))
  ) {
    throw new Error(`${name} must use HTTPS (HTTP is allowed only for local development)`);
  }
  return parsed;
}

/** Validate APP_URL as the one fixed frontend origin used for redirects. */
export function appUrlSetting(
  environment: NodeJS.ProcessEnv,
  oidcEnabled = false,
): string {
  const explicit = nonEmpty(environment, 'APP_URL');
  if (oidcEnabled && !explicit) {
    throw new Error('APP_URL must be explicitly configured when OIDC is enabled');
  }
  // Preserve the legacy fallback for non-OIDC collaboration deployments,
  // including production containers that never expose browser auth redirects.
  if (!explicit) return 'http://localhost:5173';
  const parsed = absoluteHttpUrl(
    'APP_URL',
    explicit,
    environment,
    !oidcEnabled,
  );
  if (parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new Error('APP_URL must be an origin without a path, query, or fragment');
  }
  return parsed.origin;
}

/**
 * Load the generic OpenID Connect client atomically.
 *
 * An entirely absent configuration disables OIDC. Once any required setting
 * is present, every required setting must be present so a typo cannot expose a
 * login button backed by a partially configured provider. Secrets may come
 * from the environment or a mounted secret file, but never both.
 */
export function oidcSetting(
  environment: NodeJS.ProcessEnv,
  readSecretFile: (path: string) => string = (filePath) => fs.readFileSync(filePath, 'utf8'),
): OidcSettings | null {
  const issuerUrl = nonEmpty(environment, 'OIDC_ISSUER_URL');
  const clientId = nonEmpty(environment, 'OIDC_CLIENT_ID');
  const directSecret = nonEmpty(environment, 'OIDC_CLIENT_SECRET');
  const secretFile = nonEmpty(environment, 'OIDC_CLIENT_SECRET_FILE');
  const redirectUri = nonEmpty(environment, 'OIDC_REDIRECT_URI');
  const configuredDisplayName = nonEmpty(environment, 'OIDC_DISPLAY_NAME');
  const anyRequiredSetting = Boolean(
    issuerUrl || clientId || directSecret || secretFile || redirectUri || configuredDisplayName,
  );

  if (!anyRequiredSetting) return null;
  if (directSecret && secretFile) {
    throw new Error('Set only one of OIDC_CLIENT_SECRET or OIDC_CLIENT_SECRET_FILE');
  }

  const missing: string[] = [];
  if (!issuerUrl) missing.push('OIDC_ISSUER_URL');
  if (!clientId) missing.push('OIDC_CLIENT_ID');
  if (!directSecret && !secretFile) {
    missing.push('OIDC_CLIENT_SECRET or OIDC_CLIENT_SECRET_FILE');
  }
  if (!redirectUri) missing.push('OIDC_REDIRECT_URI');
  if (missing.length > 0) {
    throw new Error(`Incomplete OIDC configuration; missing ${missing.join(', ')}`);
  }

  let clientSecret = directSecret;
  if (secretFile) {
    try {
      clientSecret = readSecretFile(secretFile).trim();
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      throw new Error(`Unable to read OIDC_CLIENT_SECRET_FILE: ${reason}`);
    }
  }
  if (!clientSecret) {
    throw new Error('OIDC client secret must not be empty');
  }

  const displayName = configuredDisplayName || 'OpenID Connect';
  if (displayName.length > 80 || /[\u0000-\u001f\u007f]/.test(displayName)) {
    throw new Error('OIDC_DISPLAY_NAME must be at most 80 characters without control characters');
  }

  const parsedIssuer = absoluteHttpUrl('OIDC_ISSUER_URL', issuerUrl!, environment);
  const parsedRedirect = absoluteHttpUrl('OIDC_REDIRECT_URI', redirectUri!, environment);
  if (parsedIssuer.search || parsedIssuer.hash) {
    throw new Error('OIDC_ISSUER_URL must not contain a query or fragment');
  }
  if (parsedRedirect.hash) {
    throw new Error('OIDC_REDIRECT_URI must not contain a fragment');
  }
  return {
    // Preserve these protocol identifiers exactly. OIDC issuer and registered
    // redirect URI comparisons are string-exact, including a trailing slash.
    issuerUrl: issuerUrl!,
    clientId: clientId!,
    clientSecret,
    redirectUri: redirectUri!,
    displayName,
    allowHttpLoopback: environment.NODE_ENV !== 'production',
  };
}
