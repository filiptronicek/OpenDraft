const fs = require("fs"),
  assert = require("assert/strict");
const root = require("path").resolve(__dirname, "..");
const Y = require(root + "/frontend/node_modules/yjs");
const { HocuspocusProvider } = require(
  root + "/frontend/node_modules/@hocuspocus/provider",
);
const WebSocket = require(root + "/collab-server/node_modules/ws");
if (!process.env.OPENDRAFT_SMOKE_ACCOUNTS)
  throw Error(
    "Set OPENDRAFT_SMOKE_ACCOUNTS to a JSON file containing two local test accounts",
  );
const accounts = JSON.parse(
  fs.readFileSync(process.env.OPENDRAFT_SMOKE_ACCOUNTS),
);
const base = "http://localhost:8080";
async function request(path, user, method = "GET", body) {
  const r = await fetch(base + path, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...(user ? { Authorization: "Bearer " + user.accessToken } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!r.ok) throw Error(`${method} ${path}: ${r.status} ${await r.text()}`);
  return r.json();
}
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function connect(id, user) {
  const doc = new Y.Doc();
  let p;
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error("sync timeout")), 15000);
    p = new HocuspocusProvider({
      url: "ws://localhost:8080/collab-server",
      name: "shared/" + id,
      document: doc,
      token: user.inviteToken || "member:" + user.accessToken,
      WebSocketPolyfill: WebSocket,
      onSynced: ({ state }) => {
        if (state) {
          clearTimeout(timer);
          resolve();
        }
      },
      onAuthenticationFailed: ({ reason }) => {
        clearTimeout(timer);
        reject(Error(reason));
      },
    });
  });
  return { doc, p };
}
(async () => {
  const owner = await request("/api/auth/login", null, "POST", accounts[0]);
  const editor = await request("/api/auth/login", null, "POST", accounts[1]);
  if (process.argv[2] === "reopen") {
    const d = JSON.parse(
      fs.readFileSync(
        require("path").join(
          require("os").tmpdir(),
          "opendraft-durable-smoke-result.json",
        ),
      ),
    );
    const c = await connect(d.id, owner);
    assert(c.doc.getXmlFragment("default").toString().includes("Offline edit"));
    c.p.destroy();
    c.doc.destroy();
    console.log("Restart and owner reopen retained offline edits.");
    return;
  }
  const project = (await request("/api/projects/", owner)).projects[0];
  const existing = (
    await request(`/api/projects/${project.id}/scripts/`, owner)
  ).find((s) => s.title === "Persistent sharing test");
  const script = existing
    ? { meta: existing }
    : await request(`/api/projects/${project.id}/scripts/`, owner, "POST", {
        title: "Persistent sharing test",
        content: {
          type: "doc",
          content: [
            { type: "action", content: [{ type: "text", text: "Original" }] },
          ],
        },
      });
  const seed = new Y.Doc(),
    paragraph = new Y.XmlElement("action");
  paragraph.insert(0, [new Y.XmlText("Original")]);
  seed.getXmlFragment("default").insert(0, [paragraph]);
  const d = await request(
    "/collab-server/api/sharing/documents",
    owner,
    "POST",
    {
      project_id: project.id,
      script_id: script.meta.id,
      initial_state: Buffer.from(Y.encodeStateAsUpdate(seed)).toString(
        "base64",
      ),
    },
  );
  await request(
    `/collab-server/api/sharing/documents/${d.id}/members/${editor.user.id}`,
    owner,
    "PUT",
    { role: "editor" },
  );
  assert(
    (await request("/collab-server/api/sharing/documents", editor)).some(
      (x) => x.id === d.id,
    ),
  );
  const navigation = await request('/api/projects/?include_shared=true', editor);
  const parent = navigation.projects.find(p => p.access === 'shared' && p.owner_id === owner.user.id && p.id === project.id);
  assert(parent, 'Existing project API should list the shared parent');
  const visibleScripts = await request(`/api/projects/${project.id}/scripts/?owner_id=${owner.user.id}`, editor);
  assert(visibleScripts.some(s => s.shared_document_id === d.id));
  assert.equal(parent.accessible_document_count, visibleScripts.length);
  const c = await connect(d.id, editor);
  assert(c.doc.getXmlFragment("default").toString().includes("Original"));
  const text = c.doc.getXmlFragment("default").get(0).get(0);
  text.insert(text.length, " Offline edit");
  await wait(3000);
  c.p.destroy();
  c.doc.destroy();
  await wait(1500);
  const saved = await request(
    `/api/projects/${project.id}/scripts/${script.meta.id}`,
    owner,
  );
  assert(JSON.stringify(saved.content).includes("Offline edit"));
  await request(
    `/collab-server/api/sharing/documents/${d.id}/members/${editor.user.id}`,
    owner,
    "PUT",
    { role: "viewer" },
  );
  const v = await connect(d.id, editor);
  v.doc.getXmlFragment("default").get(0).get(0).insert(0, "FORBIDDEN");
  v.doc.getMap("metadata").set("notes", JSON.stringify(["FORBIDDEN"]));
  await wait(1000);
  v.p.destroy();
  v.doc.destroy();
  const check = await connect(d.id, owner);
  assert(!check.doc.getXmlFragment("default").toString().includes("FORBIDDEN"));
  assert(
    !String(check.doc.getMap("metadata").get("notes")).includes("FORBIDDEN"),
  );
  check.p.destroy();
  check.doc.destroy();
  const live = await connect(d.id, editor);
  let disconnected = false;
  live.p.on("close", () => {
    disconnected = true;
    live.p.disconnect();
  });
  await request(
    `/collab-server/api/sharing/documents/${d.id}/members/${editor.user.id}`,
    owner,
    "DELETE",
  );
  await wait(1000);
  assert(disconnected, "Revocation must close an existing socket");
  live.p.destroy();
  live.doc.destroy();
  assert(
    !(await request("/collab-server/api/sharing/documents", editor)).some(
      (x) => x.id === d.id,
    ),
  );
  const guest = await request('/collab-server/api/collab/invite', owner, 'POST', {
    project_id: project.id, script_id: script.meta.id,
    collaborator_name: 'Local smoke guest', role: 'viewer', expires_in_hours: 1,
  });
  assert.equal(guest.document_name, 'shared/' + d.id);
  const guestRoom = await connect(d.id, {inviteToken: guest.token});
  assert(guestRoom.doc.getXmlFragment('default').toString().includes('Offline edit'));
  guestRoom.p.destroy(); guestRoom.doc.destroy();
  await request('/collab-server/api/collab/session', owner, 'DELETE', {token: guest.token});
  // Leave a useful editor share in the local sandbox after testing revocation.
  await request(
    `/collab-server/api/sharing/documents/${d.id}/members/${editor.user.id}`,
    owner,
    "PUT",
    { role: "editor" },
  );
  fs.writeFileSync(
    require("path").join(
      require("os").tmpdir(),
      "opendraft-durable-smoke-result.json",
    ),
    JSON.stringify(d),
  );
  console.log(
    "Local live test passed: named discovery, owner-offline editing, owner snapshot, viewer write rejection, membership removal.",
  );
})()
  .then(() => process.exit(0))
  .catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
