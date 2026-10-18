import { getCollabWsUrl } from "../config";
import { useSettingsStore } from "../stores/settingsStore";
import type { CollabSession } from "./api";
export interface GuestShare {
  token: string;
  projectId: string;
  scriptId: string;
  name: string;
  role: string;
  expiresAt: string;
}
function key() {
  return `opendraft:guest-shares:${getCollabWsUrl()}:${useSettingsStore.getState().collabAuth.user?.id || "anonymous"}`;
}
export function guestShares(): GuestShare[] {
  try {
    const v = JSON.parse(localStorage.getItem(key()) || "[]");
    return Array.isArray(v)
      ? v.filter(
          (x) =>
            typeof x.token === "string" &&
            typeof x.expiresAt === "string" &&
            Date.parse(x.expiresAt) > Date.now(),
        )
      : [];
  } catch {
    return [];
  }
}
export function rememberGuestShare(session: CollabSession, token: string) {
  const all = guestShares().filter((s) => s.token !== token);
  all.unshift({
    token,
    projectId: session.project_id,
    scriptId: session.script_id,
    name: session.project_id,
    role: session.role,
    expiresAt: session.expires_at,
  });
  try {
    localStorage.setItem(key(), JSON.stringify(all.slice(0, 100)));
  } catch {
    /* storage may be unavailable */
  }
}
export function forgetGuestShare(token: string) {
  try {
    localStorage.setItem(
      key(),
      JSON.stringify(guestShares().filter((s) => s.token !== token)),
    );
  } catch {
    /* no-op */
  }
}
