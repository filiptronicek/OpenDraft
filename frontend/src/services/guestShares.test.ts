import { beforeEach, describe, expect, it, vi } from "vitest";
const state = vi.hoisted(() => ({
  origin: "wss://one.test",
  id: undefined as string | undefined,
}));
vi.mock("../config", () => ({ getCollabWsUrl: () => state.origin }));
vi.mock("../stores/settingsStore", () => ({
  useSettingsStore: {
    getState: () => ({
      collabAuth: { user: state.id ? { id: state.id } : null },
    }),
  },
}));
import {
  guestShares,
  rememberGuestShare,
  forgetGuestShare,
} from "./guestShares";
import type { CollabSession } from "./api";
beforeEach(() => {
  const values = new Map<string, string>();
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => values.get(k) || null,
    setItem: (k: string, v: string) => values.set(k, v),
  });
  state.origin = "wss://one.test";
  state.id = undefined;
});
const session = {
  project_id: "project",
  script_id: "script",
  role: "viewer",
  expires_at: new Date(Date.now() + 60000).toISOString(),
} as CollabSession;
describe("remembered guest shares", () => {
  it("deduplicates and forgets validated links", () => {
    rememberGuestShare(session, "capability");
    rememberGuestShare(session, "capability");
    expect(guestShares()).toHaveLength(1);
    forgetGuestShare("capability");
    expect(guestShares()).toEqual([]);
  });
  it("isolates accounts and servers", () => {
    rememberGuestShare(session, "capability");
    state.id = "another-user";
    expect(guestShares()).toEqual([]);
    state.id = undefined;
    state.origin = "wss://two.test";
    expect(guestShares()).toEqual([]);
  });
  it("does not retain expired access", () => {
    rememberGuestShare(
      { ...session, expires_at: "2000-01-01T00:00:00Z" },
      "expired",
    );
    expect(guestShares()).toEqual([]);
  });
});
