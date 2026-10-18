# Persistent collaboration and shared projects

## Goal

People can find another OpenDraft user, give them persistent co-editor or viewer
access, and return to shared work from Projects. Existing guest links remain
usable and discoverable after they have been opened. Access is enforced by the
server, including already-connected clients when access changes.

## Design principles

Extend existing APIs and navigation where possible. Add dedicated endpoints only
for genuinely new operations, such as managing document membership. Sharing
follows a familiar document-sharing model: existing people and roles are visible
as soon as Share opens; restricted links and expiring bearer links are distinct.

## Scope and terminology

The current Share dialog operates on a screenplay. This first implementation
keeps that boundary: sharing one screenplay does not expose sibling scripts,
project assets, or the owner's other files. A document grant implies read-only
access to its parent's ID, name and owner, and a server-filtered list of only the
recipient's accessible documents. Projects and Open Script use the same project
navigation for owned and shared work. Project identity includes the owner ID to
avoid collisions between users' project slugs. Full-project grants can be added later as an explicit
separate operation.

There are two access types, with the same roles:

| Access | Identity | Duration | Discovery |
| --- | --- | --- | --- |
| Named member | OpenDraft user ID (including Authentik users) | Until owner removes it | Server-backed project navigation |
| Guest link | Existing bearer invite | Existing expiration/revocation rules | Remembered in the browser after successful validation |

Co-editor maps to the existing protocol role `editor`; Viewer maps to `viewer`.
The owner alone manages access. Editors edit screenplay content and shared
metadata; viewers cannot write either. Neither role can delete the owner's
project, change membership, or access unrelated scripts. Listing users does not
grant access. The user directory contains provisioned OpenDraft users, not an
unrestricted export of the Authentik directory.

## Current architecture and constraints

* `collab-server/src/db.ts` owns users and expiring `collab_sessions`.
* `routes/collab.ts` creates bearer invites; `server.ts` validates them and
  applies viewer protection to Hocuspocus connections.
* Existing room names contain a session nonce. Ending collaboration or signing
  out revokes guest sessions; these operations must not revoke named grants.
* Yjs documents already persist on the collaboration server. A durable room
  must retain its identity across owner logout, client reconnect, and restart.
* Python stores files under an authenticated-user ContextVar. A shared project
  ID alone must never change that context to another user's directory.
* `ScreenplayEditor.tsx` currently distinguishes host and guest. Host seeding,
  session-ended awareness messages, and guest-follow behavior are inappropriate
  for durable membership and need a distinct durable-session mode.
* `ProjectList.tsx` currently lists only owned projects. Shared entries must be
  separate from owned-card rename/delete/reorder controls.

## Data and authorization

Add durable `shared_documents` and `document_members` tables in the collaboration
database. A shared document has an opaque ID, owner ID, project/script IDs,
display titles, creation time and a stable room identity. Unique owner/project/
script identity prevents duplicate rooms; owner identity avoids project-slug
collisions across users. A member record is unique on document/user, has an
`editor` or `viewer` role, and timestamps. Foreign keys cascade on user deletion.
The owner is implicit and cannot be demoted through the membership API.

Membership is not a long-lived bearer token. A join requires a valid verified
account JWT plus current membership (or ownership). Deleted users, invalid JWTs,
removed memberships and unavailable database reads fail closed. Each change of
role or membership disconnects that user's existing room connections; reconnect
rechecks the current role. WebSocket authorization must not fall back to guest
access when a member JWT is expired.

Directory responses are authenticated, bounded and searchable, exposing only
ID, display name and email needed to select the intended person. No identity
provider subjects, password fields, device records or tokens are returned.

## API contract

Use a separate authenticated sharing router on the collaboration server:

* `GET /api/sharing/users?q=...`: bounded verified-user directory.
* `POST /api/sharing/documents`: register an owned screenplay and initial state.
  Verify ownership by fetching the screenplay from Python with the caller's JWT;
  do not trust a client-supplied owner ID. Existing registrations are idempotent
  and must not overwrite a live document with stale initial content.
* `GET /api/sharing/documents`: registered durable documents owned by or shared
  with the caller. This is a new endpoint, not a replacement for ordinary owned
  project/document APIs; unregistered owned documents still come from those APIs.
* Existing `GET /api/projects/?include_shared=true` merges owned projects with
  minimal shared-project projections. Default owner-only behavior is retained
  for write destinations (Save As, creating scripts) and compatibility.
* Existing `GET /api/projects/:id?owner_id=...` and
  `GET /api/projects/:id/scripts/?owner_id=...` provide minimal parent metadata
  and only permitted document descriptors. The owner ID disambiguates equal
  slugs; it never switches the request's filesystem identity.
* The backend obtains these projections from the collaboration service's
  internal `/api/sharing/projects` reads, forwarding the caller's JWT. Project
  read clients use the existing backend APIs. Counts include only permitted
  documents; no grant means 404. This grants no project mutation or asset access.
* `GET /api/sharing/documents/:id`: authorized descriptor and join identity.
* `GET /api/sharing/documents/:id/members`: owner-only access list.
* `PUT /api/sharing/documents/:id/members/:userId`: owner-only grant/role change.
* `DELETE /api/sharing/documents/:id/members/:userId`: owner-only revocation.

Return no membership data to unauthenticated guests. Use opaque IDs in routes;
the persistent WebSocket room uses that ID and a distinct token type. Existing
guest validation APIs remain compatible.

## Document lifecycle

Initialize a durable room exactly once from the owner's current screenplay,
including shared metadata. Thereafter the server's persisted Yjs document is
authoritative for that room; owners rejoining must not reseed it with stale
file content. Joining must work when the owner is offline, including for a
viewer as the first client after a server restart.

Opening an owned screenplay with a durable room rejoins it automatically.
Leaving a durable room closes only the local connection; it does not broadcast
session-ended, follow the owner's next document, revoke grants, or reset the
room. Guest sessions keep their existing explicit end-session behavior.

Owner file snapshots and exports must retain the latest collaboration content.
No migration may discard existing files or guest rooms. Validate offline-owner
editing and later owner reopen before considering this feature complete.

## Frontend

Opening Share loads existing people and active links immediately, regardless of
whether a live editing session is running. Existing people appear before the
Add people form, with role editing and Remove inline. A restricted link points
to the durable document and requires existing named access. Expiring bearer
links appear separately with their roles, expiry, Copy and Revoke controls.
The link itself never grants membership to the restricted document. Do not expose
member management to editors or viewers.

Projects merges owned and shared project cards into its ordinary grid, with a
Shared label and owner on the latter. Opening a shared project shows only
permitted screenplays, without project-management or asset controls. Open Script
also includes these projects and retains each document's co-editor/viewer role.
Named shares load from the server on every visit.
Guest entries are remembered only after successful validation and scoped by
server origin (and signed-in account where applicable). Guest secrets remain
local, are not put in logs or query strings, and retain their existing expiry.
Validate remembered links before opening; expired/revoked links show unavailable
or are removed. A local Forget action removes the shortcut, not the owner's
grant. Accountless guests can see their remembered links without receiving a
user directory or access to owned projects.

## Implementation order

1. Run isolated Compose on Colima and verify baseline auth/storage.
2. Add durable schema, directory, ownership validation and membership APIs.
3. Add durable room initialization, JWT membership authentication and immediate
   revocation/downgrade handling.
4. Add People controls, durable editor lifecycle and shared-project cards.
5. Remember validated guest links and display them alongside named shares.
6. Run authorization and multi-client lifecycle tests, then rebuild Compose and
   inspect the UI. Production deployment is a separate follow-up.

## Acceptance tests

* Owner grants editor/viewer access to distinct accounts; both see the shared
  screenplay in Projects after signing out and back in.
* A third user, guessed document ID, expired JWT and anonymous client cannot
  join or manage members. An editor cannot grant themselves owner permissions.
* Viewer writes to text and metadata are rejected by the WebSocket server.
* Editor can work with owner offline; restart preserves edits; owner reopening
  sees them without stale snapshot overwrite or duplicated initial content.
* Removal and editor-to-viewer downgrade close existing authorized connections;
  reconnect cannot regain the old permission.
* Sharing one script never exposes siblings; identical project/script IDs under
  different owners never collide.
* Owner logout does not remove named access. Guest expiry/revocation still works.
* Validated guest links appear in Projects after reload, including accountless
  use, without leaking into a different server/account's list.
* Existing owned-project CRUD, Authentik login and Gitea backup continue to work.

## Implementation notes

The local implementation uses `shared/<document UUID>` rooms and `member:<JWT>`
authentication. Existing guest invitations to a durable screenplay resolve to
that same room. The initial ProseMirror/Yjs fragment is explicitly `default`;
server snapshots use that same fragment and preserve shared metadata. Python
receives the snapshot under a server-issued owner credential on the private
backend connection, so collaborators never receive an owner's credential.

The backing screenplay is checked on join and every 15 seconds while its room
is open. A definitive 404 removes its registration and memberships; temporary
storage failures disconnect the room without deleting state. Project-level
assets are outside the screenplay grant. Guest shortcuts remain browser-local.
