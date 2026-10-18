import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  guestShares,
  forgetGuestShare,
  type GuestShare,
} from "../services/guestShares";
import { api } from "../services/api";
import { useSettingsStore } from "../stores/settingsStore";
export default function SharedProjects() {
  const navigate = useNavigate(),
    uid = useSettingsStore((s) => s.collabAuth.user?.id);
  const [guests, setGuests] = useState<GuestShare[]>([]),
    [error, setError] = useState("");
  useEffect(() => {
    setGuests(guestShares());
    setError("");
  }, [uid]);
  async function openGuest(g: GuestShare) {
    try {
      await api.validateCollabSession(g.token);
      navigate(`/collab#${encodeURIComponent(g.token)}`);
    } catch {
      setError(
        "Unable to open this guest link. Check your connection or ask the owner whether access has expired.",
      );
    }
  }
  if (guests.length === 0) return null;
  return (
    <section aria-label="Guest links" style={{ margin: "24px 0" }}>
      <h2>Guest links</h2>
      {error && <p role="alert">{error}</p>}
      {guests.map((g) => (
        <article
          key={g.token}
          className="project-card"
          style={{ padding: 16, marginBottom: 12 }}
        >
          <h3>{g.name}</h3>
          <p>
            {g.role === "editor" ? "Co-editor" : "Viewer"} · Guest access ·
            expires {new Date(g.expiresAt).toLocaleString()}
          </p>
          <button className="dialog-btn" onClick={() => openGuest(g)}>
            Open shared screenplay
          </button>
          <button
            className="dialog-btn"
            onClick={() => {
              forgetGuestShare(g.token);
              setGuests(guestShares());
            }}
          >
            Forget
          </button>
        </article>
      ))}
    </section>
  );
}
