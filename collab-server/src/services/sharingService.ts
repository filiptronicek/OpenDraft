import * as Y from "yjs";
import { yDocToProsemirrorJSON } from "y-prosemirror";
import { getDB, UserRow } from "../db";
import { generateAccessToken, verifyAccessToken } from "./tokenService";

export interface SharedDocument {
  id: string;
  owner_id: string;
  project_id: string;
  script_id: string;
  project_name: string;
  script_title: string;
  initial_state: string;
  snapshot_extras: string;
  created_at: string;
  role: "owner" | "editor" | "viewer";
  owner_name: string;
}
export const backendBase = () =>
  (process.env.BACKEND_URL || "http://localhost:8080").replace(/\/$/, "");
export async function documentAccess(
  id: string,
  userId: string,
): Promise<SharedDocument | undefined> {
  return getDB().get<SharedDocument>(
    `SELECT d.*, u.display_name AS owner_name,
    CASE WHEN d.owner_id = ? THEN 'owner' ELSE m.role END AS role
    FROM shared_documents d JOIN users u ON u.id = d.owner_id
    LEFT JOIN document_members m ON m.document_id = d.id AND m.user_id = ?
    WHERE d.id = ? AND (d.owner_id = ? OR m.user_id = ?)`,
    [userId, userId, id, userId, userId],
  );
}
export function publicDocument(d: SharedDocument) {
  const { initial_state, snapshot_extras, ...safe } = d;
  return safe;
}
export async function authenticateMember(id: string, token: string) {
  const jwt = verifyAccessToken(token);
  if (!jwt) throw new Error("Invalid or expired member token");
  const user = await getDB().get<UserRow>("SELECT * FROM users WHERE id = ?", [
    jwt.sub,
  ]);
  if (!user?.email_verified) throw new Error("Verified account required");
  const doc = await documentAccess(id, user.id);
  if (!doc) throw new Error("Shared document access denied");
  return { doc, user };
}
// Live connections are closed on role changes; message-time checks also cover
// concurrent authorization and mutation, deleted users, and multi-process changes.
const connections = new Map<
  string,
  {
    documentId: string;
    userId: string;
    close: () => void;
    timer?: ReturnType<typeof setTimeout>;
  }
>();
export function registerMemberSocket(
  socketId: string,
  documentId: string,
  userId: string,
  close: () => void,
  expiresAt?: number,
) {
  unregisterMemberSocket(socketId);
  const timer = expiresAt
    ? setTimeout(
        close,
        Math.max(1, Math.min(2147483647, expiresAt - Date.now())),
      )
    : undefined;
  timer?.unref();
  connections.set(socketId, { documentId, userId, close, timer });
}
export function unregisterMemberSocket(socketId: string) {
  clearTimeout(connections.get(socketId)?.timer);
  connections.delete(socketId);
}
export function disconnectMember(documentId: string, userId: string) {
  for (const c of connections.values())
    if (c.documentId === documentId && c.userId === userId) c.close();
}
export async function storeOwnerSnapshot(documentId: string, ydoc: Y.Doc) {
  const d = await getDB().get<SharedDocument>(
    "SELECT * FROM shared_documents WHERE id = ?",
    [documentId],
  );
  if (!d) return;
  const owner = await getDB().get<UserRow>("SELECT * FROM users WHERE id = ?", [
    d.owner_id,
  ]);
  if (!owner?.email_verified) return;
  if (ydoc.getXmlFragment("default").length === 0) return;
  const content = {
    ...JSON.parse(d.snapshot_extras),
    ...yDocToProsemirrorJSON(ydoc, "default"),
  };
  const metadata = ydoc.getMap<string>("metadata");
  const fields: Record<string, string> = {
    notes: "_notes",
    generalNotes: "_generalNotes",
    tags: "_tags",
    tagCategories: "_tagCategories",
    characterProfiles: "_characterProfiles",
    characterRelationships: "_characterRelationships",
    beats: "_beats",
    beatColumns: "_beatColumns",
    beatArrangeMode: "_beatArrangeMode",
    revisionMode: "_revisionMode",
    revisionColor: "_revisionColor",
    revisionHistory: "_revisionHistory",
    revisionSettings: "_revisionSettings",
    scriptProfile: "_scriptProfile",
  };
  for (const [key, field] of Object.entries(fields)) {
    const value = metadata.get(key);
    if (value !== undefined) content[field] = JSON.parse(value);
  }
  // Server-issued owner credential is only sent to the configured private backend,
  // never exposed to a collaborator. Membership cannot select this destination.
  const token = generateAccessToken(
    owner.id,
    owner.email,
    owner.display_name,
    true,
  );
  const result = await fetch(
    `${backendBase()}/api/projects/${encodeURIComponent(d.project_id)}/scripts/${encodeURIComponent(d.script_id)}`,
    {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ content, allow_empty_body: true }),
      signal: AbortSignal.timeout(15000),
    },
  );
  if (!result.ok)
    throw new Error(`Shared snapshot save failed (${result.status})`);
}

/** Check the backing file before opening a room. A definitive deletion also
 * removes membership; transient backend failures never discard saved data. */
export async function refreshSharedDocument(id: string): Promise<boolean> {
  const d = await getDB().get<SharedDocument>(
    "SELECT * FROM shared_documents WHERE id = ?",
    [id],
  );
  if (!d) return false;
  const owner = await getDB().get<UserRow>("SELECT * FROM users WHERE id = ?", [
    d.owner_id,
  ]);
  if (!owner?.email_verified) return false;
  const token = generateAccessToken(
    owner.id,
    owner.email,
    owner.display_name,
    true,
  );
  const result = await fetch(
    `${backendBase()}/api/projects/${encodeURIComponent(d.project_id)}/scripts/${encodeURIComponent(d.script_id)}`,
    {
      headers: { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(10000),
    },
  );
  if (result.status === 404) {
    await getDB().run("DELETE FROM shared_documents WHERE id = ?", [id]);
    return false;
  }
  if (!result.ok) throw new Error("Shared screenplay storage is unavailable");
  return true;
}
