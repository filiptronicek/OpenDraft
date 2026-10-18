import { inviteTokenDigest } from './connectionIdentity';

interface ClosableConnection {
  webSocket: { close(code?: number, reason?: string): void };
}

interface ConnectionRecord {
  connection: ClosableConnection;
  inviteDigest: string;
  expiresAt: number;
}

const FALLBACK_TOMBSTONE_MS = 5 * 60 * 1000;

/** Tracks only token digests, so raw invite capabilities never remain in memory. */
export class InviteConnectionRegistry {
  private readonly records = new Map<string, ConnectionRecord>();
  private readonly socketsByInvite = new Map<string, Set<string>>();
  /**
   * A revoke can race with Hocuspocus between async token validation and its
   * later `connected` hook. Keep a digest-only tombstone through the invite's
   * expiry so a socket that registers after the revoke is closed immediately.
   */
  private readonly revokedUntilByInvite = new Map<string, number>();

  isRevoked(inviteDigest: string, now = Date.now()): boolean {
    const revokedUntil = this.revokedUntilByInvite.get(inviteDigest);
    if (revokedUntil === undefined) return false;
    if (revokedUntil > now) return true;
    this.revokedUntilByInvite.delete(inviteDigest);
    return false;
  }

  register(
    socketId: string,
    connection: ClosableConnection,
    inviteDigest: string,
    expiresAt: string | undefined,
  ): boolean {
    this.unregister(socketId);
    const parsedExpiry = expiresAt ? Date.parse(expiresAt) : Number.NaN;
    const expiry = Number.isFinite(parsedExpiry) ? parsedExpiry : Date.now();
    if (this.isRevoked(inviteDigest) || expiry <= Date.now()) {
      connection.webSocket.close(4403, 'Invite revoked or expired');
      return false;
    }
    const record = {
      connection,
      inviteDigest,
      expiresAt: expiry,
    };
    this.records.set(socketId, record);
    const sockets = this.socketsByInvite.get(inviteDigest) || new Set<string>();
    sockets.add(socketId);
    this.socketsByInvite.set(inviteDigest, sockets);
    return true;
  }

  unregister(socketId: string): void {
    const record = this.records.get(socketId);
    if (!record) return;
    this.records.delete(socketId);
    const sockets = this.socketsByInvite.get(record.inviteDigest);
    sockets?.delete(socketId);
    if (sockets?.size === 0) this.socketsByInvite.delete(record.inviteDigest);
  }

  closeToken(token: string, expiresAt?: string): number {
    return this.closeDigest(inviteTokenDigest(token), expiresAt);
  }

  closeSessions(
    sessions: ReadonlyArray<{ token: string; expires_at?: string }>,
  ): number {
    return sessions.reduce(
      (closed, session) => closed + this.closeToken(session.token, session.expires_at),
      0,
    );
  }

  closeDigest(inviteDigest: string, expiresAt?: string): number {
    const now = Date.now();
    const parsedExpiry = expiresAt ? Date.parse(expiresAt) : Number.NaN;
    const registeredExpiry = Math.max(
      now,
      ...[...(this.socketsByInvite.get(inviteDigest) || [])]
        .map((socketId) => this.records.get(socketId)?.expiresAt || now),
    );
    const tombstoneUntil = Number.isFinite(parsedExpiry)
      ? Math.max(now + 1, parsedExpiry)
      : Math.max(now + FALLBACK_TOMBSTONE_MS, registeredExpiry);
    this.revokedUntilByInvite.set(inviteDigest, tombstoneUntil);

    const socketIds = [...(this.socketsByInvite.get(inviteDigest) || [])];
    for (const socketId of socketIds) {
      const record = this.records.get(socketId);
      if (record) record.connection.webSocket.close(4403, 'Invite revoked or expired');
    }
    return socketIds.length;
  }

  closeExpired(now = Date.now()): number {
    let closed = 0;
    for (const record of this.records.values()) {
      if (record.expiresAt <= now) {
        record.connection.webSocket.close(4403, 'Invite revoked or expired');
        closed += 1;
      }
    }
    for (const [inviteDigest, revokedUntil] of this.revokedUntilByInvite) {
      if (revokedUntil <= now) {
        this.revokedUntilByInvite.delete(inviteDigest);
      }
    }
    return closed;
  }

  get size(): number {
    return this.records.size;
  }
}

export const inviteConnections = new InviteConnectionRegistry();
