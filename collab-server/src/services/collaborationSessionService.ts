import { getDB, type CollabSessionRow, type DBAdapter } from '../db';
import {
  inviteConnections,
  type InviteConnectionRegistry,
} from './inviteConnectionRegistry';

export interface OwnedSessionRevocation {
  revoked: number;
  closed: number;
}

/**
 * Deactivate every invite owned by a user and close any live guest sockets.
 *
 * Callers that race with invite creation must hold the user's
 * AccountLifecycleGuard slot around this operation. Socket tombstones make a
 * connection that was validated just before revocation fail closed when it
 * later reaches the Hocuspocus connected hook.
 */
export async function revokeOwnedCollaborationSessions(
  userId: string,
  db: DBAdapter = getDB(),
  registry: InviteConnectionRegistry = inviteConnections,
): Promise<OwnedSessionRevocation> {
  const sessions = await db.all<Pick<CollabSessionRow, 'token' | 'expires_at'>>(
    'SELECT token, expires_at FROM collab_sessions WHERE created_by = ? AND active = 1',
    [userId],
  );

  let revoked = 0;
  let closed = 0;
  try {
    const result = await db.run(
      'UPDATE collab_sessions SET active = 0 WHERE created_by = ? AND active = 1',
      [userId],
    );
    revoked = result.changes;
  } finally {
    // Close and tombstone even if the persistence update fails. The database
    // error still propagates, but already-connected guests lose access.
    closed = registry.closeSessions(sessions);
  }

  return { revoked, closed };
}
