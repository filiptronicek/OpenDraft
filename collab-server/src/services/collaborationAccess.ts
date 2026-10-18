export type CollaborationRole = 'editor' | 'viewer';

interface ConnectionAccessConfig {
  readOnly: boolean;
}

/** Apply the server-side protocol permission represented by an invite role. */
export function applyCollaborationRole(
  connectionConfig: ConnectionAccessConfig,
  role: string,
): CollaborationRole {
  if (role !== 'editor' && role !== 'viewer') {
    throw new Error('Invalid collaboration role');
  }
  connectionConfig.readOnly = role === 'viewer';
  return role;
}
