import { useSettingsStore } from "../stores/settingsStore";
import { useEffect, useState } from "react";
import Select from "./Select";
import {
  sharingApi,
  type SharedDocument,
  type SharingUser,
  type Member,
} from "../services/sharing";
interface Props {
  projectId: string;
  scriptId: string;
  prepare: () => Promise<SharedDocument>;
}
export default function PeopleSharing({ projectId, scriptId, prepare }: Props) {
  const owner = useSettingsStore((s) => s.collabAuth.user);
  const [loading, setLoading] = useState(true);
  const [doc, setDoc] = useState<SharedDocument | null>(null),
    [users, setUsers] = useState<SharingUser[]>([]),
    [members, setMembers] = useState<Member[]>([]);
  const [query, setQuery] = useState(""),
    [selected, setSelected] = useState(""),
    [role, setRole] = useState("editor"),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  useEffect(() => {
    setLoading(true);
    sharingApi
      .documents()
      .then((ds) => {
        const d = ds.find(
          (d) =>
            d.role === "owner" &&
            d.project_id === projectId &&
            d.script_id === scriptId,
        );
        if (d) {
          setDoc(d);
          return sharingApi
            .members(d.id)
            .then(setMembers)
            .catch((e) => setError(e.message));
        }
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [projectId, scriptId]);
  useEffect(() => {
    let alive = true;
    const timer = setTimeout(
      () =>
        sharingApi
          .users(query)
          .then((u) => {
            if (alive) setUsers(u);
          })
          .catch((e) => {
            if (alive) setError(e.message);
          }),
      200,
    );
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [query]);
  async function change(userId: string, newRole?: string) {
    setBusy(true);
    setError("");
    try {
      const d = doc || (await prepare());
      setDoc(d);
      if (newRole) await sharingApi.grant(d.id, userId, newRole);
      else await sharingApi.remove(d.id, userId);
      setMembers(await sharingApi.members(d.id));
      setSelected("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section
      aria-label="People with access"
      style={{
        borderBottom: "1px solid var(--fd-border)",
        paddingBottom: 16,
        marginBottom: 16,
      }}
    >
      <h3>People with access</h3>
      <p>{owner?.displayName || "You"} (you) · Owner</p>
      {loading && <p>Loading existing access…</p>}
      <p>
        Share this screenplay until you remove access. Other scripts remain
        private.
      </p>
      {members.map((m) => (
        <div
          key={m.user_id}
          style={{
            display: "flex",
            gap: 8,
            alignItems: "center",
            marginTop: 10,
          }}
        >
          <span style={{ flex: 1, minWidth: 0 }}>
            {m.display_name}
            <small style={{ display: "block" }}>{m.email}</small>
          </span>
          <Select
            className="dialog-input"
            style={{ width: 120, flexShrink: 0 }}
            aria-label={`Role for ${m.display_name}`}
            value={m.role}
            disabled={busy}
            onChange={(e) => change(m.user_id, e.target.value)}
          >
            <option value="editor">Co-editor</option>
            <option value="viewer">Viewer</option>
          </Select>
          <button
            className="dialog-btn"
            disabled={busy}
            onClick={() => change(m.user_id)}
          >
            Remove
          </button>
        </div>
      ))}
      <h4 style={{ marginTop: 20, marginBottom: 12 }}>Add people</h4>
      <input
        className="dialog-input"
        aria-label="Find users"
        placeholder="Find a user by name or email"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
      />
      <div style={{ display: "flex", gap: 8, marginTop: 12, marginBottom: 8 }}>
        <Select
          className="dialog-input"
          aria-label="User to share with"
          value={selected}
          onChange={(e) => setSelected(e.target.value)}
          style={{ flex: 1, minWidth: 0 }}
        >
          <option value="">Select a user…</option>
          {users.map((u) => (
            <option key={u.id} value={u.id}>
              {u.display_name} ({u.email})
            </option>
          ))}
        </Select>
        <Select
          className="dialog-input"
          style={{ width: 120, flexShrink: 0 }}
          aria-label="New member role"
          value={role}
          onChange={(e) => setRole(e.target.value)}
        >
          <option value="editor">Co-editor</option>
          <option value="viewer">Viewer</option>
        </Select>
        <button
          type="button"
          className="dialog-btn"
          disabled={busy || !selected}
          onClick={() => change(selected, role)}
        >
          Share
        </button>
      </div>
      {error && <p role="alert">{error}</p>}
    </section>
  );
}
