import * as crypto from 'crypto';
import * as path from 'path';

/**
 * Map an exact canonical room name to a collision-resistant persistence file.
 * The readable prefix is diagnostic only; the SHA-256 digest is authoritative.
 */
export function documentPath(dataDir: string, documentName: string): string {
  const digest = crypto.createHash('sha256').update(documentName, 'utf8').digest('hex');
  const prefix = documentName
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48) || 'room';
  return path.resolve(dataDir, `${prefix}-${digest}.yjs`);
}
