import * as crypto from 'crypto';

export function inviteTokenDigest(inviteToken: string): string {
  return crypto.createHash('sha256').update(inviteToken, 'utf8').digest('hex');
}

/**
 * Authenticated connections are limited per account. Accountless guests are
 * limited per invite, never by their host-controlled display name and never
 * using the raw bearer token as a map/log key.
 */
export function connectionLimitKey(
  userId: string | null,
  inviteToken: string,
): string {
  if (userId) return `user:${userId}`;
  return `invite:${inviteTokenDigest(inviteToken)}`;
}
