import * as jwt from 'jsonwebtoken';
import * as crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { getDB } from '../db';
import { config } from '../config';
import { secretDigest } from './secretDigest';

export interface AccessTokenPayload {
  sub: string;
  email: string;
  name: string;
  email_verified: boolean;
  type: 'access';
}

export function generateAccessToken(
  userId: string,
  email: string,
  name: string,
  emailVerified: boolean,
): string {
  const payload: AccessTokenPayload = {
    sub: userId,
    email,
    name,
    email_verified: emailVerified,
    type: 'access',
  };
  return jwt.sign(payload, config.jwtSecret, {
    algorithm: 'HS256',
    issuer: config.jwtIssuer,
    audience: config.jwtAudience,
    expiresIn: config.jwtAccessExpiry as any,
    jwtid: uuidv4(),
  });
}

export async function generateRefreshToken(
  userId: string,
  deviceId: string | null = null,
): Promise<{ token: string; expiresAt: string }> {
  const db = getDB();
  const token = crypto.randomBytes(48).toString('base64url');
  const tokenHash = secretDigest(token);
  const id = uuidv4();
  const now = new Date();

  // Parse refresh expiry (e.g. '7d' -> 7 days)
  const match = config.jwtRefreshExpiry.match(/^(\d+)([smhd])$/);
  let expiresMs = 7 * 24 * 60 * 60 * 1000; // default 7 days
  if (match) {
    const num = parseInt(match[1], 10);
    const unit = match[2];
    const multipliers: Record<string, number> = { s: 1000, m: 60000, h: 3600000, d: 86400000 };
    expiresMs = num * (multipliers[unit] || 86400000);
  }

  const expiresAt = new Date(now.getTime() + expiresMs).toISOString();

  await db.run(
    `INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, revoked, created_at, device_id)
     VALUES (?, ?, ?, ?, 0, ?, ?)`,
    [id, userId, tokenHash, expiresAt, now.toISOString(), deviceId],
  );

  return { token, expiresAt };
}

export function verifyAccessToken(token: string): AccessTokenPayload | null {
  try {
    const payload = jwt.verify(token, config.jwtSecret, {
      algorithms: ['HS256'],
      issuer: config.jwtIssuer,
      audience: config.jwtAudience,
    }) as AccessTokenPayload;
    if (
      payload.type !== 'access'
      || typeof payload.sub !== 'string'
      || !payload.sub
      || typeof payload.email !== 'string'
      || !payload.email
      || typeof payload.name !== 'string'
      || !payload.name
      || typeof payload.email_verified !== 'boolean'
    ) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

export async function rotateRefreshToken(oldToken: string): Promise<{ accessToken: string; refreshToken: string; userId: string } | null> {
  const db = getDB();
  const now = new Date().toISOString();

  const matchedRow = await db.get<{ id: string; user_id: string; device_id: string | null }>(
    `SELECT id, user_id, device_id FROM refresh_tokens
     WHERE token_hash = ? AND revoked = 0 AND expires_at > ?`,
    [secretDigest(oldToken), now],
  );

  if (!matchedRow) return null;

  // Look up user for new access token
  const user = await db.get<{
    email: string;
    display_name: string;
    email_verified: number;
  }>(
    'SELECT email, display_name, email_verified FROM users WHERE id = ?',
    [matchedRow.user_id],
  );
  if (!user) return null;

  // Claim the old credential exactly once. Two concurrent requests may both
  // compare its hash, but only one is allowed to complete the rotation.
  const revoked = await db.run(
    'UPDATE refresh_tokens SET revoked = 1 WHERE id = ? AND revoked = 0',
    [matchedRow.id],
  );
  if (revoked.changes !== 1) return null;

  // Issue new pair, preserving the device binding so the new refresh token
  // is still attributable to the same device for the devices list / revoke.
  const accessToken = generateAccessToken(
    matchedRow.user_id,
    user.email,
    user.display_name,
    Boolean(user.email_verified),
  );
  const { token: refreshToken } = await generateRefreshToken(matchedRow.user_id, matchedRow.device_id);

  return { accessToken, refreshToken, userId: matchedRow.user_id };
}

export async function revokeAllRefreshTokens(userId: string): Promise<void> {
  const db = getDB();
  await db.run('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?', [userId]);
}

export async function revokeRefreshToken(token: string): Promise<boolean> {
  const db = getDB();
  const now = new Date().toISOString();
  const result = await db.run(
    `UPDATE refresh_tokens SET revoked = 1
     WHERE token_hash = ? AND revoked = 0 AND expires_at > ?`,
    [secretDigest(token), now],
  );
  return result.changes === 1;
}
