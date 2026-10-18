import { getCollabWsUrl } from "../config";
import { authedFetch } from "./authedFetch";
export interface SharedDocument {
  id: string;
  owner_id: string;
  owner_name: string;
  project_id: string;
  script_id: string;
  project_name: string;
  script_title: string;
  role: "owner" | "editor" | "viewer";
}
export const sharedProjectPath = (p: {
  id: string;
  owner_id?: string | null;
}) =>
  `/project/${encodeURIComponent(p.id)}/shared-by/${encodeURIComponent(p.owner_id || "")}`;
export interface SharingUser {
  id: string;
  display_name: string;
  email: string;
}
export interface Member {
  user_id: string;
  display_name: string;
  email: string;
  role: "editor" | "viewer";
}
async function request<T>(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const res = await authedFetch(
    `${getCollabWsUrl().replace(/^ws/, "http")}/api/sharing${path}`,
    {
      method,
      headers: { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    },
  );
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.error || `Sharing unavailable (${res.status})`);
  }
  return res.json();
}
export const sharingApi = {
  users: (q = "") =>
    request<SharingUser[]>(`/users?q=${encodeURIComponent(q)}`),
  documents: () => request<SharedDocument[]>("/documents"),
  document: (id: string) =>
    request<SharedDocument>(`/documents/${encodeURIComponent(id)}`),
  create: (body: unknown) =>
    request<SharedDocument>("/documents", "POST", body),
  members: (id: string) => request<Member[]>(`/documents/${id}/members`),
  grant: (id: string, userId: string, role: string) =>
    request(`/documents/${id}/members/${userId}`, "PUT", { role }),
  remove: (id: string, userId: string) =>
    request(`/documents/${id}/members/${userId}`, "DELETE"),
};
