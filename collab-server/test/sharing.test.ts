import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as http from "node:http";
import express from "express";
import * as Y from "yjs";

test("persistent sharing enforces ownership, account identity, roles and revocation", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "opendraft-sharing-"));
  process.env.DATA_DIR = dir;
  process.env.JWT_SECRET = "sharing-tests-only-secret-32-characters";
  process.env.DB_TYPE = "sqlite";
  const { initDB } = await import("../src/db");
  const db = await initDB();
  const { generateAccessToken, verifyAccessToken } =
    await import("../src/services/tokenService");
  const {
    authenticateMember,
    documentAccess,
    registerMemberSocket,
    storeOwnerSnapshot,
    refreshSharedDocument,
  } = await import("../src/services/sharingService");
  const { default: router } = await import("../src/routes/sharing");
  const now = new Date().toISOString();
  for (const id of ["owner", "editor", "viewer", "outsider"])
    await db.run(
      "INSERT INTO users(id,email,email_verified,display_name,created_at,updated_at) VALUES(?,?,1,?,?,?)",
      [id, `${id}@example.test`, id, now, now],
    );
  const tokens = Object.fromEntries(
    ["owner", "editor", "viewer", "outsider"].map((id) => [
      id,
      generateAccessToken(id, `${id}@example.test`, id, true),
    ]),
  );
  let snapshot: any;
  let deleted = false;
  const backend = http.createServer((req, res) => {
    res.setHeader("Content-Type", "application/json");
    if (deleted) {
      res.writeHead(404);
      res.end("{}");
      return;
    }
    if (
      verifyAccessToken(req.headers.authorization?.slice(7) || "")?.sub !==
      "owner"
    ) {
      res.writeHead(404);
      res.end("{}");
      return;
    }
    if (req.method === "PUT") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        snapshot = JSON.parse(body);
        res.end("{}");
      });
      return;
    }
    res.end(
      JSON.stringify(
        req.url?.includes("/scripts/")
          ? { meta: { title: "Screenplay" } }
          : { name: "Project" },
      ),
    );
  });
  await new Promise<void>((r) => backend.listen(0, "127.0.0.1", r));
  process.env.BACKEND_URL = `http://127.0.0.1:${(backend.address() as any).port}`;
  const app = express();
  app.use(express.json({ limit: "16mb" }));
  app.use(router);
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((r) => server.once("listening", r));
  const base = `http://127.0.0.1:${(server.address() as any).port}`;
  async function request(
    url: string,
    user?: string,
    method = "GET",
    body?: unknown,
  ) {
    return fetch(base + url, {
      method,
      headers: {
        "Content-Type": "application/json",
        ...(user ? { Authorization: `Bearer ${tokens[user]}` } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  }
  try {
    assert.equal((await request("/users")).status, 401);
    const users = (await (await request("/users", "owner")).json()) as any[];
    assert.equal(users.length, 3);
    assert.deepEqual(Object.keys(users[0]).sort(), [
      "display_name",
      "email",
      "id",
    ]);
    const seed = new Y.Doc(),
      element = new Y.XmlElement("action");
    element.insert(0, [new Y.XmlText("Original")]);
    seed.getXmlFragment("default").insert(0, [element]);
    const body = {
      project_id: "project",
      script_id: "script",
      initial_state: Buffer.from(Y.encodeStateAsUpdate(seed)).toString(
        "base64",
      ),
    };
    assert.equal(
      (await request("/documents", "outsider", "POST", body)).status,
      404,
    );
    const created = await request("/documents", "owner", "POST", body);
    assert.equal(created.status, 201);
    const doc = (await created.json()) as any;
    assert.equal(doc.initial_state, undefined);
    await storeOwnerSnapshot(doc.id, seed);
    assert.equal(snapshot.content.content[0].content[0].text, "Original");
    const duplicate = (await (
      await request("/documents", "owner", "POST", body)
    ).json()) as any;
    assert.equal(duplicate.id, doc.id);
    assert.equal(
      (await request(`/documents/${doc.id}`, "outsider")).status,
      404,
    );
    assert.equal(
      (
        await request(
          `/documents/${doc.id}/members/editor`,
          "outsider",
          "PUT",
          { role: "editor" },
        )
      ).status,
      403,
    );
    for (const role of ["editor", "viewer"])
      assert.equal(
        (
          await request(
            `/documents/${doc.id}/members/${role}`,
            "owner",
            "PUT",
            { role },
          )
        ).status,
        200,
      );
    assert.equal(
      (await authenticateMember(doc.id, tokens.viewer)).doc.role,
      "viewer",
    );
    assert.equal(
      (await authenticateMember(doc.id, tokens.editor)).doc.role,
      "editor",
    );
    // An unshared sibling must not affect a recipient's project listing/count.
    const hidden = (await (
      await request("/documents", "owner", "POST", {
        ...body,
        script_id: "private-sibling",
      })
    ).json()) as any;
    const projects = (await (
      await request("/projects", "viewer")
    ).json()) as any[];
    assert.equal(projects.length, 1);
    assert.equal(projects[0].document_count, 1);
    assert.deepEqual(
      projects[0].documents.map((d: any) => d.id),
      [doc.id],
    );
    assert.deepEqual(Object.keys(projects[0]).sort(), [
      "document_count",
      "documents",
      "id",
      "name",
      "owner_id",
      "owner_name",
    ]);
    const visibleProject = await request("/projects/owner/project", "viewer");
    assert.equal(visibleProject.status, 200);
    assert.equal(
      JSON.stringify(await visibleProject.json()).includes(hidden.id),
      false,
    );
    assert.equal(
      (await request(`/documents/${hidden.id}`, "viewer")).status,
      404,
    );
    assert.equal(
      (await request("/projects/owner/project", "outsider")).status,
      404,
    );
    assert.equal(
      (await request("/projects/outsider/project", "viewer")).status,
      404,
    );
    assert.equal((await request("/projects")).status, 401);
    // Identical project slugs under different owners remain distinct.
    await db.run(
      `INSERT INTO shared_documents
      (id, owner_id, project_id, script_id, project_name, script_title, initial_state, snapshot_extras, created_at)
      SELECT 'other-owner-document', 'outsider', project_id, script_id, project_name, 'Other owner screenplay', initial_state, snapshot_extras, created_at
      FROM shared_documents WHERE id = ?`,
      [doc.id],
    );
    await db.run(
      `INSERT INTO document_members(document_id,user_id,role,updated_at) VALUES('other-owner-document','viewer','editor',?)`,
      [now],
    );
    const colliding = (await (
      await request("/projects", "viewer")
    ).json()) as any[];
    assert.equal(colliding.length, 2);
    assert.deepEqual(colliding.map((p) => p.owner_id).sort(), [
      "outsider",
      "owner",
    ]);
    const otherProject = (await (
      await request("/projects/outsider/project", "viewer")
    ).json()) as any;
    assert.deepEqual(
      otherProject.documents.map((d: any) => d.id),
      ["other-owner-document"],
    );
    assert.equal(otherProject.documents[0].role, "editor");
    await db.run(
      "DELETE FROM shared_documents WHERE id = 'other-owner-document'",
    );
    await assert.rejects(authenticateMember(doc.id, "invalid"));
    await assert.rejects(authenticateMember(doc.id, tokens.outsider));
    assert.equal(
      (
        await request(`/documents/${doc.id}/members/viewer`, "editor", "PUT", {
          role: "editor",
        })
      ).status,
      403,
    );
    assert.equal(
      (
        await request(`/documents/${doc.id}/members/owner`, "owner", "PUT", {
          role: "viewer",
        })
      ).status,
      400,
    );
    let closed = 0;
    registerMemberSocket("test", doc.id, "editor", () => {
      closed++;
    });
    await request(`/documents/${doc.id}/members/editor`, "owner", "PUT", {
      role: "viewer",
    });
    assert.equal(closed, 1);
    assert.equal(
      (await authenticateMember(doc.id, tokens.editor)).doc.role,
      "viewer",
    );
    await request(`/documents/${doc.id}/members/editor`, "owner", "DELETE");
    assert.equal(closed, 2);
    await assert.rejects(authenticateMember(doc.id, tokens.editor));
    assert.equal(await documentAccess(doc.id, "editor"), undefined);
    assert.equal(
      (await request("/projects/owner/project", "editor")).status,
      404,
    );
    assert.deepEqual(await (await request("/projects", "editor")).json(), []);
    assert.equal(
      ((await (await request("/documents", "viewer")).json()) as any[]).length,
      1,
    );
    assert.equal(await refreshSharedDocument(doc.id), true);
    deleted = true;
    assert.equal(await refreshSharedDocument(doc.id), false);
    assert.equal(await documentAccess(doc.id, "owner"), undefined);
    await db.run("DELETE FROM users WHERE id = ?", ["viewer"]);
    await assert.rejects(authenticateMember(doc.id, tokens.viewer));
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    await new Promise<void>((r) => backend.close(() => r()));
    await db.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
