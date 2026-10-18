import { Router } from "express";
import { randomUUID } from "crypto";
import * as Y from "yjs";
import { z } from "zod";
import { getDB } from "../db";
import { requireVerifiedAuth } from "../middleware/auth";
import {
  backendBase,
  documentAccess,
  publicDocument,
  disconnectMember,
  SharedDocument,
} from "../services/sharingService";
const router = Router();
router.use(requireVerifiedAuth);
router.get("/users", async (req, res) => {
  const q =
    typeof req.query.q === "string" ? req.query.q.trim().slice(0, 100) : "";
  const users = await getDB().all(
    `SELECT id, display_name, email FROM users WHERE email_verified = 1 AND id != ?
    AND (LOWER(display_name) LIKE ? OR LOWER(email) LIKE ?) ORDER BY display_name LIMIT 50`,
    [req.user!.id, `%${q.toLowerCase()}%`, `%${q.toLowerCase()}%`],
  );
  res.json(users);
});
router.get("/documents", async (req, res) => {
  const uid = req.user!.id;
  const docs = await getDB().all<SharedDocument>(
    `SELECT d.*, u.display_name AS owner_name,
    CASE WHEN d.owner_id = ? THEN 'owner' ELSE m.role END AS role
    FROM shared_documents d JOIN users u ON u.id = d.owner_id
    LEFT JOIN document_members m ON m.document_id = d.id AND m.user_id = ?
    WHERE d.owner_id = ? OR m.user_id = ? ORDER BY d.created_at DESC`,
    [uid, uid, uid, uid],
  );
  res.json(docs.map(publicDocument));
});
// These are navigation projections of document grants, not project grants.
async function sharedProjects(userId: string) {
  const rows = await getDB().all<SharedDocument>(
    `SELECT d.*, u.display_name AS owner_name, m.role FROM document_members m
     JOIN shared_documents d ON d.id = m.document_id
     JOIN users u ON u.id = d.owner_id
     WHERE m.user_id = ? AND d.owner_id != ? ORDER BY d.project_name, d.script_title`,
    [userId, userId],
  );
  const projects = new Map<
    string,
    {
      id: string;
      name: string;
      owner_id: string;
      owner_name: string;
      documents: ReturnType<typeof publicDocument>[];
    }
  >();
  for (const d of rows) {
    const key = JSON.stringify([d.owner_id, d.project_id]);
    let project = projects.get(key);
    if (!project) {
      project = {
        id: d.project_id,
        name: d.project_name,
        owner_id: d.owner_id,
        owner_name: d.owner_name,
        documents: [],
      };
      projects.set(key, project);
    }
    project.documents.push(publicDocument(d));
  }
  return [...projects.values()].map((p) => ({
    ...p,
    document_count: p.documents.length,
  }));
}
router.get("/projects", async (req, res) => {
  res.json(await sharedProjects(req.user!.id));
});
router.get("/projects/:ownerId/:projectId", async (req, res) => {
  const project = (await sharedProjects(req.user!.id)).find(
    (p) => p.owner_id === req.params.ownerId && p.id === req.params.projectId,
  );
  if (!project) {
    res.status(404).json({ error: "Project unavailable" });
    return;
  }
  res.json(project);
});
const create = z.object({
  project_id: z.string().min(1).max(128),
  script_id: z.string().min(1).max(128),
  initial_state: z.string().min(1).max(12_000_000),
  snapshot_extras: z.record(z.string(), z.unknown()).default({}),
});
router.post("/documents", async (req, res) => {
  const parsed = create.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid shared document" });
    return;
  }
  const input = parsed.data,
    uid = req.user!.id;
  const headers = { Authorization: req.headers.authorization! };
  const root = `${backendBase()}/api/projects/${encodeURIComponent(input.project_id)}`;
  const [project, script] = await Promise.all([
    fetch(root, { headers, signal: AbortSignal.timeout(10000) }),
    fetch(`${root}/scripts/${encodeURIComponent(input.script_id)}`, {
      headers,
      signal: AbortSignal.timeout(10000),
    }),
  ]);
  if (!project.ok || !script.ok) {
    res.status(404).json({ error: "Owned screenplay not found" });
    return;
  }
  const existing = await getDB().get<{ id: string }>(
    "SELECT id FROM shared_documents WHERE owner_id = ? AND project_id = ? AND script_id = ?",
    [uid, input.project_id, input.script_id],
  );
  if (existing) {
    res.json(publicDocument((await documentAccess(existing.id, uid))!));
    return;
  }
  const doc = new Y.Doc();
  try {
    Y.applyUpdate(doc, Buffer.from(input.initial_state, "base64"));
    if (!doc.getXmlFragment("default").length) throw new Error();
  } catch {
    res.status(400).json({ error: "Invalid initial screenplay state" });
    return;
  } finally {
    doc.destroy();
  }
  const p = (await project.json()) as { name: string },
    s = (await script.json()) as { meta: { title: string } };
  const id = randomUUID();
  await getDB().run(
    `INSERT INTO shared_documents (id,owner_id,project_id,script_id,project_name,script_title,initial_state,snapshot_extras,created_at)
    VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(owner_id,project_id,script_id) DO NOTHING`,
    [
      id,
      uid,
      input.project_id,
      input.script_id,
      p.name,
      s.meta.title,
      input.initial_state,
      JSON.stringify(input.snapshot_extras),
      new Date().toISOString(),
    ],
  );
  const row = await getDB().get<{ id: string }>(
    "SELECT id FROM shared_documents WHERE owner_id = ? AND project_id = ? AND script_id = ?",
    [uid, input.project_id, input.script_id],
  );
  res.status(201).json(publicDocument((await documentAccess(row!.id, uid))!));
});
router.get("/documents/:id", async (req, res) => {
  const d = await documentAccess(String(req.params.id), req.user!.id);
  if (!d) {
    res.status(404).json({ error: "Shared screenplay unavailable" });
    return;
  }
  res.json(publicDocument(d));
});
router.get("/documents/:id/members", async (req, res) => {
  const d = await documentAccess(String(req.params.id), req.user!.id);
  if (d?.role !== "owner") {
    res.status(403).json({ error: "Only the owner can manage access" });
    return;
  }
  res.json(
    await getDB().all(
      `SELECT m.user_id, m.role, u.display_name, u.email FROM document_members m
    JOIN users u ON u.id=m.user_id WHERE m.document_id = ? ORDER BY u.display_name`,
      [d.id],
    ),
  );
});
router.put("/documents/:id/members/:userId", async (req, res) => {
  const d = await documentAccess(String(req.params.id), req.user!.id);
  if (d?.role !== "owner") {
    res.status(403).json({ error: "Only the owner can manage access" });
    return;
  }
  const role = z.enum(["editor", "viewer"]).safeParse(req.body.role),
    userId = String(req.params.userId);
  if (!role.success || userId === d.owner_id) {
    res.status(400).json({ error: "Invalid member or role" });
    return;
  }
  const user = await getDB().get(
    "SELECT id FROM users WHERE id = ? AND email_verified = 1",
    [userId],
  );
  if (!user) {
    res.status(404).json({ error: "Verified user not found" });
    return;
  }
  await getDB().run(
    `INSERT INTO document_members(document_id,user_id,role,updated_at) VALUES(?,?,?,?)
    ON CONFLICT(document_id,user_id) DO UPDATE SET role=excluded.role,updated_at=excluded.updated_at`,
    [d.id, userId, role.data, new Date().toISOString()],
  );
  disconnectMember(d.id, userId);
  res.json({ ok: true });
});
router.delete("/documents/:id/members/:userId", async (req, res) => {
  const d = await documentAccess(String(req.params.id), req.user!.id);
  if (d?.role !== "owner") {
    res.status(403).json({ error: "Only the owner can manage access" });
    return;
  }
  const userId = String(req.params.userId);
  await getDB().run(
    "DELETE FROM document_members WHERE document_id = ? AND user_id = ?",
    [d.id, userId],
  );
  disconnectMember(d.id, userId);
  res.json({ ok: true });
});
export default router;
