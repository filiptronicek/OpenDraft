import { getDB } from '../db';
import type { CollabSessionRow } from '../db';
import { inviteTokenDigest } from './connectionIdentity';

export interface CollabSession {
  token: string;
  project_id: string;
  script_id: string;
  collaborator_name: string;
  role: string;
  active: boolean;
  session_nonce?: string;
  created_at?: string;
  expires_at?: string;
}

type RoomIdentity = Pick<CollabSession, 'project_id' | 'script_id' | 'session_nonce'>;

export interface CanonicalRoom {
  projectId: string;
  scriptId: string;
  sessionNonce: string;
}

function isSafeRoomSegment(value: unknown, maxLength = 128): value is string {
  if (
    typeof value !== 'string'
    || value.length < 1
    || value.length > maxLength
    || value !== value.trim()
  ) {
    return false;
  }
  for (const char of value) {
    const code = char.charCodeAt(0);
    if (char === '/' || char === '\\' || code < 32 || code === 127) return false;
  }
  return true;
}

/** Return the one and only Yjs room name represented by an invite. */
export function canonicalDocumentName(session: RoomIdentity): string | null {
  if (!isSafeRoomSegment(session.project_id) || !isSafeRoomSegment(session.script_id)) {
    return null;
  }
  const nonce = session.session_nonce || '';
  if (nonce && !isSafeRoomSegment(nonce, 128)) return null;
  return nonce
    ? `${session.project_id}/${session.script_id}/${nonce}`
    : `${session.project_id}/${session.script_id}`;
}

export function isSessionBoundToDocument(
  session: RoomIdentity,
  documentName: string,
): boolean {
  return canonicalDocumentName(session) === documentName;
}

export function parseCanonicalDocumentName(documentName: string): CanonicalRoom | null {
  const parts = documentName.split('/');
  if (parts.length !== 2 && parts.length !== 3) return null;
  const room = { projectId: parts[0], scriptId: parts[1], sessionNonce: parts[2] || '' };
  const canonical = canonicalDocumentName({
    project_id: room.projectId,
    script_id: room.scriptId,
    session_nonce: room.sessionNonce,
  });
  return canonical === documentName ? room : null;
}

/**
 * Validate an invite token.
 * The collab database is the sole invite authority.
 */
export async function validateInviteToken(token: string): Promise<CollabSession | null> {
  const tokenId = inviteTokenDigest(token).slice(0, 12);

  // Check the authoritative collaboration database.
  try {
    const db = getDB();
    const session = await db.get<CollabSessionRow>(
      'SELECT * FROM collab_sessions WHERE token = ? AND active = 1',
      [token],
    );
    if (session && new Date(session.expires_at) > new Date()) {
      console.log(`[validateToken] ${tokenId} → found in collab-server DB`);
      return {
        token: session.token,
        project_id: session.project_id,
        script_id: session.script_id,
        collaborator_name: session.collaborator_name,
        role: session.role,
        active: true,
        session_nonce: session.session_nonce,
        created_at: session.created_at,
        expires_at: session.expires_at,
      };
    }
    console.log(`[validateToken] ${tokenId} → not found in collab-server DB`);
  } catch (err) {
    console.log(`[validateToken] ${tokenId} → DB query failed:`, err);
  }
  return null;
}
