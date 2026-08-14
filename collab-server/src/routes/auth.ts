import { Router } from 'express';
import { z } from 'zod';
import { OAuth2Client } from 'google-auth-library';
import * as userService from '../services/userService';
import type { UserRow } from '../db';
import * as tokenService from '../services/tokenService';
import * as emailService from '../services/emailService';
import * as auditService from '../services/auditService';
import * as deviceService from '../services/deviceService';
import * as passwordResetService from '../services/passwordResetService';
import type { DeviceInfo } from '../services/deviceService';
import { requireAuth } from '../middleware/auth';
import {
  oidcCallbackLimiter,
  oidcExchangeLimiter,
  oidcStartLimiter,
  strictLimiter,
  veryStrictLimiter,
} from '../middleware/rateLimit';
import { config } from '../config';
import { accountLifecycle } from '../services/accountLifecycle';
import { revokeOwnedCollaborationSessions } from '../services/collaborationSessionService';
import { OidcClientService } from '../services/oidcClientService';
import {
  clearOidcTransactionCookie,
  OIDC_HANDOFF_TTL_MS,
  OIDC_TRANSACTION_COOKIE,
  OIDC_TRANSACTION_TTL_MS,
  oidcStateStore,
  oidcTransactionCookie,
  parseCookie,
  safeReturnTo,
} from '../services/oidcStateService';

const router = Router();
const oidcClient = config.oidc ? new OidcClientService(config.oidc) : null;

// ── Validation schemas ──

const deviceInfoSchema = z.object({
  deviceId: z.string().min(8).max(128),
  deviceName: z.string().min(1).max(120),
  platform: z.string().max(64).optional().nullable(),
}).optional();

const passwordRule = z.string().min(8).max(128).regex(
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$/,
  'Password must contain at least one uppercase letter, one lowercase letter, and one digit'
);

const registerSchema = z.object({
  email: z.string().email().max(255),
  password: passwordRule,
  displayName: z.string().min(1).max(100),
  device: deviceInfoSchema,
});

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
  device: deviceInfoSchema,
});

const refreshSchema = z.object({
  refreshToken: z.string().min(1),
});

const verifyEmailSchema = z.object({
  code: z.string().length(6),
});

const verifyEmailLinkSchema = z.object({
  email: z.string().email().max(255),
  code: z.string().length(6),
});

const googleLoginSchema = z.object({
  idToken: z.string().min(1),
  device: deviceInfoSchema,
});

const oidcExchangeSchema = z.object({
  code: z.string().min(32).max(256),
  device: deviceInfoSchema,
});

const verifyDeviceSchema = z.object({
  challengeId: z.string().min(8).max(128),
  code: z.string().length(6),
});

const resendDeviceChallengeSchema = z.object({
  challengeId: z.string().min(8).max(128),
});

const changePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: passwordRule,
});

const forgotPasswordSchema = z.object({
  email: z.string().email().max(255),
});

const resetPasswordSchema = z.object({
  // The token is base64url-encoded 32 random bytes (~43 chars). Cap generously.
  token: z.string().min(16).max(256),
  newPassword: passwordRule,
});

const deleteAccountSchema = z.object({
  // Password confirmation when the user has one. Google-only accounts can
  // omit this and supply confirmation: 'DELETE' instead.
  password: z.string().optional(),
  confirmation: z.string().optional(),
});

// ── Helpers ──

function userResponse(user: UserRow | null) {
  if (!user) return null;
  const authMethods: string[] = [];
  if (user.password_hash) authMethods.push('local');
  if (user.google_id) authMethods.push('google');
  if (Number(user.external_identity_count || 0) > 0) authMethods.push('oidc');
  return {
    id: user.id,
    email: user.email,
    displayName: user.display_name,
    emailVerified: Boolean(user.email_verified),
    twoFactorEnabled: Boolean(user.two_factor_enabled),
    hasPassword: Boolean(user.password_hash),
    authMethods,
  };
}

function accessTokenFor(user: UserRow): string {
  return tokenService.generateAccessToken(
    user.id,
    user.email,
    user.display_name,
    Boolean(user.email_verified),
  );
}

function isOidcOnly(user: UserRow): boolean {
  return Number(user.external_identity_count || 0) > 0
    && !user.password_hash
    && !user.google_id;
}

function getClientIp(req: any): string {
  return req.ip || req.connection?.remoteAddress || 'unknown';
}

function pickDeviceInfo(req: any, body: any): DeviceInfo | null {
  const device = body?.device;
  if (!device || typeof device.deviceId !== 'string' || typeof device.deviceName !== 'string') {
    return null;
  }
  return {
    deviceId: device.deviceId,
    deviceName: device.deviceName,
    platform: typeof device.platform === 'string' ? device.platform : null,
    userAgent: typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : null,
    ipAddress: getClientIp(req),
  };
}

function oidcFrontendCallback(parameters: Record<string, string>): string {
  const callback = new URL('/auth/oidc/callback', config.appUrl);
  for (const [name, value] of Object.entries(parameters)) {
    callback.searchParams.set(name, value);
  }
  return callback.toString();
}

function oidcCallbackFailure(res: any, error: string): void {
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.redirect(302, oidcFrontendCallback({ error }));
}

async function beginOidcTransaction(input: {
  returnTo: string;
  linkUserId?: string | null;
}): Promise<{ authorizationUrl: string; cookie: string }> {
  if (!oidcClient) throw new Error('OIDC is not configured');
  const transaction = oidcStateStore.createTransaction(
    input.returnTo,
    input.linkUserId || null,
  );
  const authorizationUrl = await oidcClient.authorizationUrl({
    state: transaction.state,
    nonce: transaction.nonce,
    codeChallenge: transaction.codeChallenge,
  });
  return {
    authorizationUrl,
    cookie: oidcTransactionCookie(
      transaction.cookieValue,
      Math.ceil(OIDC_TRANSACTION_TTL_MS / 1000),
    ),
  };
}

export function requiresDeviceForTwoFactor(
  twoFactorEnabled: number | boolean,
  deviceInfo: DeviceInfo | null,
): boolean {
  return Boolean(twoFactorEnabled) && !deviceInfo;
}

function deviceResponse(row: {
  device_id: string;
  device_name: string;
  platform: string | null;
  user_agent: string | null;
  ip_address: string | null;
  trusted: number;
  first_seen_at: string;
  last_seen_at: string;
}, currentDeviceId?: string | null): Record<string, unknown> {
  return {
    deviceId: row.device_id,
    deviceName: row.device_name,
    platform: row.platform,
    userAgent: row.user_agent,
    ipAddress: row.ip_address,
    trusted: Boolean(row.trusted),
    firstSeenAt: row.first_seen_at,
    lastSeenAt: row.last_seen_at,
    current: currentDeviceId ? row.device_id === currentDeviceId : false,
  };
}

// ── Routes ──

router.post('/register', veryStrictLimiter, async (req, res) => {
  try {
    if (!config.localRegistrationEnabled) {
      res.status(403).json({ error: 'Local account registration is disabled on this server' });
      return;
    }

    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten().fieldErrors });
      return;
    }

    const { email, password, displayName } = parsed.data;
    const deviceInfo = pickDeviceInfo(req, parsed.data);

    // Check if email already exists
    const existing = await userService.findUserByEmail(email);
    if (existing) {
      res.status(409).json({ error: 'Email already registered' });
      return;
    }

    let user = await userService.createUser(email, password, displayName);
    // The device that created the account is implicitly trusted — no 2FA prompt
    // on the very first login.
    if (deviceInfo) {
      await deviceService.recordTrustedDevice(user.id, deviceInfo);
    }

    // Send verification email if SMTP is configured, otherwise auto-verify
    if (config.smtpHost) {
      const code = await emailService.createVerificationCode(user.id);
      await emailService.sendVerificationEmail(user.email, code);
    } else {
      await userService.setEmailVerified(user.id);
      user = (await userService.findUserById(user.id))!;
    }

    // Issue credentials only after account setup and any automatic email
    // verification, so the signed claims reflect the final user state.
    const accessToken = accessTokenFor(user);
    const { token: refreshToken } = await tokenService.generateRefreshToken(
      user.id,
      deviceInfo?.deviceId ?? null,
    );

    await auditService.logEvent('register', user.id, null, { email: user.email }, getClientIp(req));

    res.status(201).json({
      user: userResponse(user),
      accessToken,
      refreshToken,
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/login', strictLimiter, async (req, res) => {
  try {
    if (!config.localLoginEnabled) {
      res.status(403).json({ error: 'Local password login is disabled on this server' });
      return;
    }
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid input' });
      return;
    }

    const { email, password } = parsed.data;
    const deviceInfo = pickDeviceInfo(req, parsed.data);
    const user = await userService.findUserByEmail(email);

    if (!(await userService.verifyPassword(user, password)) || !user) {
      await auditService.logEvent('login_failed', null, null, { reason: 'invalid_credentials' }, getClientIp(req));
      res.status(401).json({ error: 'Invalid email or password' });
      return;
    }

    if (requiresDeviceForTwoFactor(user.two_factor_enabled, deviceInfo)) {
      await auditService.logEvent(
        'login_failed',
        user.id,
        null,
        { reason: 'two_factor_device_required' },
        getClientIp(req),
      );
      res.status(400).json({ error: 'Device information is required for two-factor verification' });
      return;
    }

    // Device tracking + (opt-in) new-device 2FA.
    //
    //   • If 2FA is enabled and the (user, device) pair is new, we email a
    //     6-digit code and respond with a challenge — no tokens are issued
    //     until the client posts the code to /verify-device.
    //   • If 2FA is off (default), login proceeds normally; the device is
    //     recorded as trusted and we email a "new device signed in" notice
    //     so the user can spot unauthorized access.
    //   • Older clients without device info remain compatible only when 2FA is
    //     disabled; 2FA accounts must identify a device before tokens issue.
    if (deviceInfo) {
      const known = await deviceService.findDevice(user.id, deviceInfo.deviceId);
      if (!known) {
        if (user.two_factor_enabled) {
          const challenge = await deviceService.createDeviceChallenge(user.id, deviceInfo);
          if (!challenge) {
            res.status(429).json({ error: 'Too many new-device verification attempts. Please try again later.' });
            return;
          }
          await emailService.sendNewDeviceCode(
            user.email,
            challenge.code,
            deviceInfo.deviceName,
            deviceInfo.ipAddress ?? null,
          );
          await auditService.logEvent(
            'new_device_challenge',
            user.id,
            null,
            { device: deviceInfo.deviceName, deviceId: deviceInfo.deviceId },
            getClientIp(req),
          );
          res.status(200).json({
            deviceVerificationRequired: true,
            challengeId: challenge.challengeId,
            message: 'A verification code was emailed to confirm this new device.',
          });
          return;
        }
        // 2FA off — record the device and notify by email (best-effort).
        await deviceService.recordTrustedDevice(user.id, deviceInfo);
        try {
          await emailService.sendNewDeviceNotice(
            user.email,
            deviceInfo.deviceName,
            deviceInfo.ipAddress ?? null,
          );
        } catch { /* notification only — never block login */ }
      } else {
        await deviceService.touchDevice(user.id, deviceInfo.deviceId, deviceInfo.ipAddress ?? null);
      }
    }

    const accessToken = accessTokenFor(user);
    const { token: refreshToken } = await tokenService.generateRefreshToken(
      user.id,
      deviceInfo?.deviceId ?? null,
    );

    await auditService.logEvent('login', user.id, null, { email: user.email }, getClientIp(req));

    res.json({
      user: userResponse(user),
      accessToken,
      refreshToken,
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/verify-device', strictLimiter, async (req, res) => {
  try {
    const parsed = verifyDeviceSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid input' });
      return;
    }

    const challenge = await deviceService.consumeDeviceChallenge(
      parsed.data.challengeId,
      parsed.data.code,
    );
    if (!challenge) {
      res.status(400).json({ error: 'Invalid or expired verification code' });
      return;
    }

    const user = await userService.findUserById(challenge.user_id);
    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    await deviceService.recordTrustedDevice(user.id, {
      deviceId: challenge.device_id,
      deviceName: challenge.device_name,
      userAgent: challenge.user_agent,
      platform: challenge.platform,
      ipAddress: challenge.ip_address,
    });

    const accessToken = accessTokenFor(user);
    const { token: refreshToken } = await tokenService.generateRefreshToken(user.id, challenge.device_id);

    await auditService.logEvent(
      'new_device_verified',
      user.id,
      null,
      { device: challenge.device_name, deviceId: challenge.device_id },
      getClientIp(req),
    );

    res.json({
      user: userResponse(user),
      accessToken,
      refreshToken,
    });
  } catch (err) {
    console.error('Verify device error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * Re-issue a new-device verification code for an existing pending challenge.
 *
 * Used by the frontend when the user clicks "Resend code" — we look up the
 * original challenge to recover the (user, device) context, generate a fresh
 * code, and email it. The old challenge is invalidated by createDeviceChallenge.
 *
 * Security: callers don't need to be authenticated (they got into this flow
 * because they typed a correct password but were challenged for a new device).
 * The challengeId itself is the proof — it's a uuidv4 the client only knows
 * because /login just returned it. The hourly per-user rate limit inside
 * createDeviceChallenge stops resend-spam abuse.
 */
router.post('/resend-device-challenge', strictLimiter, async (req, res) => {
  try {
    const parsed = resendDeviceChallengeSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid input' });
      return;
    }

    if (!config.smtpHost) {
      res.status(400).json({
        error: 'Email is not configured on this server — cannot resend the verification code.',
      });
      return;
    }

    const existing = await deviceService.findChallengeById(parsed.data.challengeId);
    if (!existing) {
      res.status(404).json({ error: 'Challenge not found' });
      return;
    }

    const user = await userService.findUserById(existing.user_id);
    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    const fresh = await deviceService.createDeviceChallenge(user.id, {
      deviceId: existing.device_id,
      deviceName: existing.device_name,
      userAgent: existing.user_agent,
      platform: existing.platform,
      ipAddress: existing.ip_address,
    });
    if (!fresh) {
      res.status(429).json({ error: 'Too many verification attempts. Please try again later.' });
      return;
    }

    await emailService.sendNewDeviceCode(
      user.email,
      fresh.code,
      existing.device_name,
      existing.ip_address,
    );

    await auditService.logEvent(
      'new_device_challenge_resend',
      user.id,
      null,
      { device: existing.device_name, deviceId: existing.device_id },
      getClientIp(req),
    );

    res.json({
      challengeId: fresh.challengeId,
      message: 'A new verification code was sent to your email.',
    });
  } catch (err) {
    console.error('Resend device challenge error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/refresh', strictLimiter, async (req, res) => {
  try {
    const parsed = refreshSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid input' });
      return;
    }

    const result = await tokenService.rotateRefreshToken(parsed.data.refreshToken);
    if (!result) {
      res.status(401).json({ error: 'Invalid or expired refresh token' });
      return;
    }

    await auditService.logEvent('token_refresh', result.userId, null, null, getClientIp(req));

    res.json({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
    });
  } catch (err) {
    console.error('Refresh error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/logout', strictLimiter, async (req, res) => {
  try {
    const parsed = refreshSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid input' });
      return;
    }

    await tokenService.revokeRefreshToken(parsed.data.refreshToken);
    await auditService.logEvent('logout', null, null, null, getClientIp(req));

    res.json({ message: 'Logged out' });
  } catch (err) {
    console.error('Logout error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/verify-email', requireAuth, veryStrictLimiter, async (req, res) => {
  try {
    const parsed = verifyEmailSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid code format' });
      return;
    }

    const valid = await emailService.validateVerificationCode(req.user!.id, parsed.data.code);
    if (!valid) {
      res.status(400).json({ error: 'Invalid or expired verification code' });
      return;
    }

    await userService.setEmailVerified(req.user!.id);
    const freshUser = await userService.findUserById(req.user!.id);
    if (!freshUser) {
      res.status(404).json({ error: 'User not found' });
      return;
    }
    const accessToken = accessTokenFor(freshUser);
    await auditService.logEvent('email_verified', freshUser.id, null, null, getClientIp(req));

    res.json({
      message: 'Email verified',
      user: userResponse(freshUser),
      accessToken,
    });
  } catch (err) {
    console.error('Verify email error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Magic-link variant: unauthenticated — the link emailed to the user carries
// {email, code}. Validates the code, marks email as verified, and returns a
// fresh token pair so the frontend can log the user in on click.
router.post('/verify-email-link', veryStrictLimiter, async (req, res) => {
  try {
    const parsed = verifyEmailLinkSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten().fieldErrors });
      return;
    }

    const user = await userService.findUserByEmail(parsed.data.email);
    if (!user) {
      res.status(400).json({ error: 'Invalid or expired verification link' });
      return;
    }

    const valid = await emailService.validateVerificationCode(user.id, parsed.data.code);
    if (!valid) {
      res.status(400).json({ error: 'Invalid or expired verification link' });
      return;
    }

    await userService.setEmailVerified(user.id);
    const freshUser = (await userService.findUserById(user.id))!;

    const accessToken = accessTokenFor(freshUser);
    const { token: refreshToken } = await tokenService.generateRefreshToken(freshUser.id);

    await auditService.logEvent('email_verified', freshUser.id, null, { via: 'magic_link' }, getClientIp(req));

    res.json({
      user: userResponse(freshUser),
      accessToken,
      refreshToken,
    });
  } catch (err) {
    console.error('Verify email-link error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/resend-verification', requireAuth, veryStrictLimiter, async (req, res) => {
  try {
    const user = await userService.findUserById(req.user!.id);
    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    if (user.email_verified) {
      res.status(400).json({ error: 'Email already verified' });
      return;
    }

    const code = await emailService.createVerificationCode(user.id);
    await emailService.sendVerificationEmail(user.email, code);

    res.json({ message: 'Verification email sent' });
  } catch (err) {
    console.error('Resend verification error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Generic OpenID Connect (Authorization Code + PKCE) ──

router.get('/oidc/start', oidcStartLimiter, async (req, res) => {
  if (!oidcClient) {
    res.status(501).json({ error: 'OpenID Connect is not configured on this server' });
    return;
  }
  try {
    const started = await beginOidcTransaction({
      returnTo: safeReturnTo(req.query.returnTo),
    });
    res.setHeader('Set-Cookie', started.cookie);
    res.setHeader('Cache-Control', 'no-store');
    res.redirect(302, started.authorizationUrl);
  } catch (error) {
    console.error(
      'OIDC authorization start failed:',
      error instanceof Error ? error.name : 'UnknownError',
    );
    res.status(503).json({ error: 'OpenID Connect provider is temporarily unavailable' });
  }
});

router.post('/oidc/link/start', requireAuth, oidcStartLimiter, async (req, res) => {
  if (!oidcClient) {
    res.status(501).json({ error: 'OpenID Connect is not configured on this server' });
    return;
  }
  try {
    const started = await beginOidcTransaction({
      returnTo: safeReturnTo(req.body?.returnTo),
      linkUserId: req.user!.id,
    });
    res.setHeader('Set-Cookie', started.cookie);
    res.setHeader('Cache-Control', 'no-store');
    res.json({ authorizationUrl: started.authorizationUrl });
  } catch (error) {
    console.error(
      'OIDC link start failed:',
      error instanceof Error ? error.name : 'UnknownError',
    );
    res.status(503).json({ error: 'OpenID Connect provider is temporarily unavailable' });
  }
});

router.get('/oidc/callback', oidcCallbackLimiter, async (req, res) => {
  res.setHeader('Set-Cookie', clearOidcTransactionCookie());
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
  if (!oidcClient || !config.oidc) {
    oidcCallbackFailure(res, 'oidc_unavailable');
    return;
  }

  const state = typeof req.query.state === 'string' && req.query.state.length <= 256
    ? req.query.state
    : null;
  const cookieValue = parseCookie(req.headers.cookie, OIDC_TRANSACTION_COOKIE);
  const transaction = state
    ? oidcStateStore.consumeTransaction(state, cookieValue)
    : null;
  if (!state || !transaction) {
    oidcCallbackFailure(res, 'invalid_state');
    return;
  }
  if (typeof req.query.error === 'string') {
    oidcCallbackFailure(res, 'provider_error');
    return;
  }
  const code = typeof req.query.code === 'string' && req.query.code.length <= 4096
    ? req.query.code
    : null;
  if (!code) {
    oidcCallbackFailure(res, 'invalid_response');
    return;
  }

  try {
    const identity = await oidcClient.verifyCallback({
      code,
      state,
      nonce: transaction.nonce,
      codeVerifier: transaction.codeVerifier,
    });
    const user = transaction.linkUserId
      ? await userService.linkExternalIdentity(transaction.linkUserId, identity)
      : await userService.findOrCreateExternalUser(identity);
    if (transaction.linkUserId) {
      await auditService.logEvent(
        'oidc_link',
        user.id,
        null,
        { issuer: identity.issuer },
        getClientIp(req),
      );
    }
    const handoff = oidcStateStore.createHandoff(user.id, transaction.returnTo);
    // Rotate the browser binding: possession of a handoff URL alone is not
    // sufficient to redeem OpenDraft credentials.
    res.setHeader(
      'Set-Cookie',
      oidcTransactionCookie(
        handoff.cookieValue,
        Math.ceil(OIDC_HANDOFF_TTL_MS / 1000),
      ),
    );
    res.redirect(302, oidcFrontendCallback({ code: handoff.code }));
  } catch (error) {
    // Never forward provider errors, codes, or token details to the browser.
    console.error(
      'OIDC callback failed:',
      error instanceof Error ? error.name : 'UnknownError',
    );
    if (error instanceof userService.ExternalIdentityEmailConflictError) {
      oidcCallbackFailure(res, 'account_link_required');
      return;
    }
    if (error instanceof userService.ExternalIdentityAlreadyLinkedError) {
      oidcCallbackFailure(res, 'identity_already_linked');
      return;
    }
    if (error instanceof userService.ExternalIdentityEmailMismatchError) {
      oidcCallbackFailure(res, 'link_email_mismatch');
      return;
    }
    oidcCallbackFailure(res, 'authentication_failed');
  }
});

router.post('/oidc/exchange', oidcExchangeLimiter, async (req, res) => {
  res.setHeader('Set-Cookie', clearOidcTransactionCookie());
  res.setHeader('Cache-Control', 'no-store');
  if (!oidcClient) {
    res.status(501).json({ error: 'OpenID Connect is not configured on this server' });
    return;
  }
  const parsed = oidcExchangeSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid input' });
    return;
  }
  const bindingCookie = parseCookie(req.headers.cookie, OIDC_TRANSACTION_COOKIE);
  const handoff = oidcStateStore.consumeHandoff(parsed.data.code, bindingCookie);
  if (!handoff) {
    res.status(400).json({ error: 'Invalid or expired sign-in code' });
    return;
  }

  try {
    const user = await userService.findUserById(handoff.userId);
    if (!user) {
      res.status(400).json({ error: 'Invalid or expired sign-in code' });
      return;
    }
    const deviceInfo = pickDeviceInfo(req, parsed.data);
    // Authentik is authoritative for MFA. A device supplied after a successful
    // OIDC flow is trusted without invoking OpenDraft's email challenge.
    if (deviceInfo) {
      await deviceService.recordTrustedDevice(user.id, deviceInfo);
    }
    const accessToken = accessTokenFor(user);
    const { token: refreshToken } = await tokenService.generateRefreshToken(
      user.id,
      deviceInfo?.deviceId ?? null,
    );
    await auditService.logEvent(
      'oidc_login',
      user.id,
      null,
      null,
      getClientIp(req),
    );
    res.json({
      user: userResponse(user),
      accessToken,
      refreshToken,
      returnTo: handoff.returnTo,
    });
  } catch (error) {
    console.error(
      'OIDC handoff exchange failed:',
      error instanceof Error ? error.name : 'UnknownError',
    );
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/google', strictLimiter, async (req, res) => {
  try {
    if (!config.googleClientId) {
      res.status(501).json({ error: 'Google login is not configured on this server' });
      return;
    }

    const parsed = googleLoginSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid input' });
      return;
    }

    const client = new OAuth2Client(config.googleClientId);
    const ticket = await client.verifyIdToken({
      idToken: parsed.data.idToken,
      audience: config.googleClientId,
    });

    const payload = ticket.getPayload();
    if (!payload || !payload.email || !payload.sub || payload.email_verified !== true) {
      res.status(400).json({ error: 'Invalid Google token' });
      return;
    }

    const user = await userService.findOrCreateGoogleUser(
      payload.sub,
      payload.email,
      payload.name || payload.email.split('@')[0],
    );

    const deviceInfo = pickDeviceInfo(req, parsed.data);
    if (deviceInfo) {
      await deviceService.recordTrustedDevice(user.id, deviceInfo);
    }

    const accessToken = accessTokenFor(user);
    const { token: refreshToken } = await tokenService.generateRefreshToken(
      user.id,
      deviceInfo?.deviceId ?? null,
    );

    await auditService.logEvent('google_login', user.id, null, { email: user.email }, getClientIp(req));

    res.json({
      user: userResponse(user),
      accessToken,
      refreshToken,
    });
  } catch (err) {
    console.error('Google login error:', err);
    res.status(401).json({ error: 'Google authentication failed' });
  }
});

router.get('/me', requireAuth, async (req, res) => {
  try {
    const user = await userService.findUserById(req.user!.id);
    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }
    res.json(userResponse(user));
  } catch (err) {
    console.error('Get me error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Return whether Google login is available (for frontend UI)
router.get('/config', (req, res) => {
  res.json({
    localLoginEnabled: config.localLoginEnabled,
    localRegistrationEnabled: config.localRegistrationEnabled,
    googleEnabled: Boolean(config.googleClientId),
    oidcEnabled: Boolean(config.oidc),
    oidcDisplayName: config.oidc?.displayName || '',
    emailVerificationRequired: Boolean(config.smtpHost),
    // Whether outbound email is wired up. UI gates 2FA on this — without
    // SMTP, the new-device code can't be delivered, so enabling it would
    // lock users out of new devices.
    smtpConfigured: Boolean(config.smtpHost),
  });
});

// ── Change password ──
router.post('/change-password', requireAuth, veryStrictLimiter, async (req, res) => {
  try {
    const parsed = changePasswordSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten().fieldErrors });
      return;
    }

    const user = await userService.findUserById(req.user!.id);
    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    if (!user.password_hash) {
      res.status(400).json({ error: 'This account does not use a local password.' });
      return;
    }

    if (!(await userService.verifyPassword(user, parsed.data.currentPassword))) {
      await auditService.logEvent(
        'login_failed',
        user.id,
        null,
        { reason: 'change_password_wrong_current' },
        getClientIp(req),
      );
      res.status(401).json({ error: 'Current password is incorrect' });
      return;
    }

    if (parsed.data.currentPassword === parsed.data.newPassword) {
      res.status(400).json({ error: 'New password must be different from the current password' });
      return;
    }

    const changed = await accountLifecycle.runActive(user.id, async () => {
      await userService.updatePassword(user.id, parsed.data.newPassword);
      // Invalidate refresh credentials and long-lived invite capabilities.
      await tokenService.revokeAllRefreshTokens(user.id);
      await revokeOwnedCollaborationSessions(user.id);
    });
    if (!changed.accepted) {
      res.status(409).json({ error: 'Account deletion is in progress' });
      return;
    }

    await auditService.logEvent('password_changed', user.id, null, null, getClientIp(req));

    // Best-effort notification email — don't fail the request if SMTP fails.
    const ua = typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : 'Unknown device';
    try { await emailService.sendPasswordChangedNotice(user.email, ua); } catch { /* ignore */ }

    res.json({ message: 'Password updated. Please sign in again on all devices.' });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Forgot password / reset password ──
//
// The flow is:
//   1. User submits their email to /forgot-password. Server generates a
//      single-use token, stores its SHA-256 digest, and emails the user a link
//      containing the raw token. The response is intentionally generic —
//      "if an account exists, an email was sent" — to avoid leaking which
//      addresses are registered.
//   2. User opens the link in the frontend, which collects a new password
//      and POSTs it with the token to /reset-password. Server validates,
//      updates password_hash, invalidates every refresh token, and emails a
//      "your password was changed" notice. Google-only accounts can use this
//      flow to *set* an initial password (the email itself is proof of
//      identity).
//
// Both endpoints require outbound SMTP — without it the email never reaches
// the user and the flow stalls, so we return a clear error.

router.post('/forgot-password', veryStrictLimiter, async (req, res) => {
  try {
    const parsed = forgotPasswordSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid input' });
      return;
    }

    if (!config.smtpHost) {
      res.status(503).json({
        error:
          'Password reset is unavailable: this server has no email service configured. ' +
          'Contact the administrator.',
      });
      return;
    }

    const genericMessage =
      'If an account with that email exists, a password-reset link was sent to it. ' +
      'The link expires in 30 minutes.';

    const user = await userService.findUserByEmail(parsed.data.email);
    // Recovery for OIDC-only users belongs to the identity provider. Keep the
    // same generic response so this does not reveal account or auth methods.
    if (user && !isOidcOnly(user)) {
      const created = await passwordResetService.createResetToken(user.id, getClientIp(req));
      try {
        await emailService.sendPasswordResetEmail(user.email, created.token, getClientIp(req));
      } catch (err) {
        // Log but do not surface — keeps the response identical for valid
        // and invalid email enumeration attempts.
        console.error('Failed to send password reset email:', err);
      }
      await auditService.logEvent(
        'password_reset_requested',
        user.id,
        null,
        { email: user.email },
        getClientIp(req),
      );
    } else if (!user) {
      await auditService.logEvent(
        'password_reset_requested',
        null,
        null,
        { email: parsed.data.email, reason: 'user_not_found' },
        getClientIp(req),
      );
    } else {
      await auditService.logEvent(
        'password_reset_requested',
        user.id,
        null,
        { reason: 'managed_by_oidc_provider' },
        getClientIp(req),
      );
    }

    // Always respond identically so callers can't enumerate registered emails.
    res.json({ message: genericMessage });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/reset-password', veryStrictLimiter, async (req, res) => {
  try {
    const parsed = resetPasswordSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten().fieldErrors });
      return;
    }

    const userId = await passwordResetService.consumeResetToken(parsed.data.token);
    if (!userId) {
      await auditService.logEvent(
        'password_reset_failed',
        null,
        null,
        { reason: 'invalid_or_expired_token' },
        getClientIp(req),
      );
      res.status(400).json({ error: 'Invalid or expired reset link. Request a new one.' });
      return;
    }

    const user = await userService.findUserById(userId);
    if (!user) {
      res.status(400).json({ error: 'Invalid or expired reset link. Request a new one.' });
      return;
    }

    const reset = await accountLifecycle.runActive(user.id, async () => {
      await userService.updatePassword(user.id, parsed.data.newPassword);
      // Clicking the reset link also proves control of the email address.
      if (!user.email_verified) {
        await userService.setEmailVerified(user.id);
      }
      // Revoke credentials and collaboration capabilities from before recovery.
      await tokenService.revokeAllRefreshTokens(user.id);
      await revokeOwnedCollaborationSessions(user.id);
    });
    if (!reset.accepted) {
      res.status(400).json({ error: 'Invalid or expired reset link. Request a new one.' });
      return;
    }

    await auditService.logEvent('password_reset', user.id, null, null, getClientIp(req));

    // Best-effort notification email.
    const ua = typeof req.headers['user-agent'] === 'string'
      ? req.headers['user-agent']
      : 'Unknown device';
    try { await emailService.sendPasswordChangedNotice(user.email, ua); } catch { /* ignore */ }

    res.json({ message: 'Password updated. You can now sign in with your new password.' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Devices ──
router.get('/devices', requireAuth, async (req, res) => {
  try {
    const devices = await deviceService.listDevices(req.user!.id);
    const currentDeviceId = typeof req.headers['x-device-id'] === 'string'
      ? req.headers['x-device-id']
      : null;
    res.json({
      devices: devices.map((d) => deviceResponse(d, currentDeviceId)),
    });
  } catch (err) {
    console.error('List devices error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.delete('/devices/:deviceId', requireAuth, async (req, res) => {
  try {
    const rawDeviceId = req.params.deviceId;
    const deviceId = Array.isArray(rawDeviceId) ? rawDeviceId[0] : rawDeviceId;
    if (!deviceId || typeof deviceId !== 'string' || deviceId.length > 128) {
      res.status(400).json({ error: 'Invalid deviceId' });
      return;
    }
    const removed = await deviceService.deleteDevice(req.user!.id, deviceId);
    if (!removed) {
      res.status(404).json({ error: 'Device not found' });
      return;
    }
    await auditService.logEvent(
      'device_revoked',
      req.user!.id,
      null,
      { deviceId },
      getClientIp(req),
    );
    res.json({ message: 'Device revoked' });
  } catch (err) {
    console.error('Revoke device error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Two-factor verification preference ──
const twoFactorSchema = z.object({ enabled: z.boolean() });

router.post('/two-factor', requireAuth, async (req, res) => {
  try {
    const parsed = twoFactorSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid input' });
      return;
    }
    const currentUser = await userService.findUserById(req.user!.id);
    if (!currentUser) {
      res.status(404).json({ error: 'User not found' });
      return;
    }
    if (isOidcOnly(currentUser)) {
      res.status(400).json({
        error: 'Two-factor authentication for this account is managed by the identity provider.',
      });
      return;
    }
    // Reject enabling 2FA when outbound email isn't wired up — without it,
    // the new-device code never reaches the user and they get locked out.
    // Disabling is always allowed so an admin who turned SMTP off can still
    // unblock existing accounts.
    if (parsed.data.enabled && !config.smtpHost) {
      res.status(400).json({
        error:
          'Email is not configured on this server, so two-factor verification cannot be enabled. ' +
          'Configure SMTP and try again.',
      });
      return;
    }
    await userService.setTwoFactorEnabled(req.user!.id, parsed.data.enabled);
    const fresh = await userService.findUserById(req.user!.id);
    res.json({ user: userResponse(fresh) });
  } catch (err) {
    console.error('Toggle 2FA error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Account deletion (Apple Guideline 5.1.1(v)) ──
//
// Permanently deletes the user record and every server-side artifact that
// belongs to it. The frontend is expected to clear local state and prompt the
// user to download any cloud screenplays *before* hitting this endpoint —
// the server cannot recover deleted data.
router.delete('/account', requireAuth, veryStrictLimiter, async (req, res) => {
  try {
    const parsed = deleteAccountSchema.safeParse(req.body || {});
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid input' });
      return;
    }

    const user = await userService.findUserById(req.user!.id);
    if (!user) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    // For password accounts: require current password. For Google-only
    // accounts the JWT itself is sufficient, but require the literal string
    // "DELETE" as a typed confirmation so it cannot be triggered by accident.
    if (user.password_hash) {
      if (!parsed.data.password) {
        res.status(400).json({ error: 'Password is required to confirm account deletion' });
        return;
      }
      if (!(await userService.verifyPassword(user, parsed.data.password))) {
        await auditService.logEvent(
          'login_failed',
          user.id,
          null,
          { reason: 'delete_account_wrong_password' },
          getClientIp(req),
        );
        res.status(401).json({ error: 'Password is incorrect' });
        return;
      }
    } else {
      if (parsed.data.confirmation !== 'DELETE') {
        res.status(400).json({ error: 'Type DELETE to confirm account deletion' });
        return;
      }
    }

    const emailForNotice = user.email;
    const deletion = await accountLifecycle.runDeletion(user.id, async (markDeletion) => {
      // Query, deactivate, close, and tombstone owned invites while the
      // per-user deletion lock excludes in-process invite creation.
      await revokeOwnedCollaborationSessions(user.id);
      await userService.deleteUser(user.id, undefined, markDeletion);
    });
    if (!deletion.accepted) {
      res.status(409).json({ error: 'Account deletion is already in progress' });
      return;
    }

    await auditService.logEvent('account_deleted', null, null, null, getClientIp(req));

    try { await emailService.sendAccountDeletedNotice(emailForNotice); } catch { /* ignore */ }

    res.json({ message: 'Account deleted' });
  } catch (err) {
    console.error('Delete account error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
