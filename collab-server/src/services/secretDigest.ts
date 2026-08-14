import * as crypto from 'crypto';

export function secretDigest(value: string): string {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}
