# Private OpenDraft deployment

This fork supports a small self-hosted writers' room with local accounts,
generic OpenID Connect login, and an optional private Gitea mirror for manual
version checkpoints.

## Track the source fork

Keep the public project as **upstream** and use your GitHub fork as **origin**.
For a normal clone whose public remote is still named **origin**, rename it
first:

~~~sh
git remote rename origin upstream
git remote add origin https://github.com/OWNER/OpenDraft.git
git push -u origin ft/private-hardening
git remote -v
~~~

The source fork and the Gitea checkpoint repository below are separate. Do not
use the checkpoint repository as the code remote; they have different access
and recovery purposes.

## Deploy from this fork

The source-build stack contains the fork's changes:

~~~sh
cd deploy
cp .env.example .env
# Edit .env, then:
./deploy.sh
~~~

The command **./deploy.sh --combined** requires **OPENDRAFT_IMAGE** to name an
image built from this fork. It fails rather than falling back to the public
upstream image, because that image does not contain this fork's OIDC, auth, and
backup changes. Set **OPENDRAFT_VERSION** to a pinned tag as well.

The deployment exposes the editor at **https://DEMO_HOST**, including the
same-origin **/collab-server** WebSocket/HTTP transport. The separate
**COLLAB_HOST** remains available for desktop and mobile clients. The
**/collab/:token** path belongs to the browser invite page and is deliberately
not proxied to the collaboration server.

These Compose topologies trust Caddy on Docker's private network when deriving
client IPs for authentication and WebSocket limits. If you modify the stack to
publish the backend or collaboration port directly, narrow
**BACKEND_FORWARDED_ALLOW_IPS** and **TRUSTED_PROXY_IPS** to the exact proxy
addresses instead of trusting the Compose-network defaults.

## Local account authentication

Generate a unique **JWT_SECRET** with at least 32 random bytes and keep the
issuer and audience identical in both services. Compose wires these values to
the backend and collaboration server.

For a local-account-only first boot:

1. Keep **LOCAL_REGISTRATION_ENABLED=true**.
2. Create the accounts that should host collaboration sessions.
3. Set **LOCAL_REGISTRATION_ENABLED=false**.
4. Redeploy.

Disabling registration is enforced by the server, not only hidden in the UI.
Existing users can continue to sign in.

`LOCAL_LOGIN_ENABLED` is a separate switch. Keep it `true` until OIDC login and
account linking have both been tested. Setting it to `false` removes and blocks
local password sign-in without disabling OIDC.

Without SMTP, new accounts are verified automatically. With SMTP configured,
OpenDraft requires the emailed verification code and enables password reset
and new-device email checks. Do not set a placeholder **SMTP_HOST**: either
configure all SMTP values or leave it unset.

Browser access and refresh tokens remain in `localStorage`. Deploy this fork
only on a trusted TLS origin and do not install unreviewed plugins. Before
offering it as a public multi-tenant service, move refresh tokens to Secure,
HttpOnly, SameSite cookies, keep access tokens in memory only, and enforce a
strict Content Security Policy.

## Sign in through Authentik

OpenDraft uses the OIDC Authorization Code flow with PKCE. Authentik owns
passwords, MFA, recovery, and access policy; OpenDraft exchanges the verified
identity for its existing short-lived application session. Authentik tokens and
OpenDraft session tokens are never placed in a redirect URL. This first OIDC
integration targets the hosted web app; native clients need a future system
browser/deep-link flow.

In Authentik:

1. Create an **OAuth2/OpenID Provider** with client type **Confidential**.
2. Add the strict redirect URI
   `https://scripts.example.com/api/auth/oidc/callback`.
3. Make the `openid`, `profile`, and `email` scope mappings available. The
   returned email must have an `email_verified: true` claim.
4. Create an application for that provider and apply the desired group and MFA
   policies in Authentik.
5. Copy the provider's issuer URL, client ID, and client secret. An Authentik
   issuer normally resembles
   `https://auth.example.com/application/o/opendraft/`.

Store only the client secret in a root-readable host file:

~~~sh
install -m 600 /dev/null /secure/path/opendraft-oidc-client-secret
# Edit the file and place only the client secret in it.
~~~

Then add all of these settings to `deploy/.env`:

~~~dotenv
LOCAL_LOGIN_ENABLED=true
LOCAL_REGISTRATION_ENABLED=false
OIDC_ISSUER_URL=https://auth.example.com/application/o/opendraft/
OIDC_CLIENT_ID=replace-with-authentik-client-id
OIDC_REDIRECT_URI=https://scripts.example.com/api/auth/oidc/callback
OIDC_CLIENT_SECRET_HOST_FILE=/secure/path/opendraft-oidc-client-secret
OIDC_DISPLAY_NAME=Authentik
~~~

`deploy.sh` validates the settings as one unit and mounts the secret read-only.
It will not start a partially configured OIDC deployment. The issuer must use
HTTPS in production and must exactly match the issuer in Authentik discovery
and signed ID tokens.

Do not add Authentik's forward-auth middleware in front of this deployment.
OpenDraft is itself the OIDC relying party, and an additional proxy login gate
can interrupt the callback and WebSocket flow.

On first rollout, sign in locally, open account settings, and use **Link
Authentik**. This explicitly attaches Authentik's stable `(issuer, subject)`
identity to the existing OpenDraft user and preserves project ownership. An
ordinary OIDC login never auto-links by matching email; if that email already
belongs to a local user, OpenDraft rejects the login until the authenticated
link flow is used. After linking and testing a fresh login in a private browser,
`LOCAL_LOGIN_ENABLED` may be set to `false`.

SMTP may remain unset for an OIDC-only deployment. Authentik must perform email
verification before emitting `email_verified: true`; do not hard-code that
claim to true merely to bypass verification. Disabling a user in Authentik does
not immediately revoke an already-issued OpenDraft refresh session, so keep the
OpenDraft refresh lifetime appropriate for the deployment and explicitly sign
out active users during urgent revocation.

## Mirror checkpoints to Gitea

Create one empty private Gitea repository, for example
**film/opendraft-backups**. Create a dedicated token with repository write
permission only; OpenDraft does not need Gitea admin or repository-creation
permission.

Store the token outside the checkout:

~~~sh
install -m 600 /dev/null /secure/path/opendraft-gitea-token
# Edit the file and place only the token in it.
~~~

Add this to **deploy/.env**:

~~~dotenv
OPENDRAFT_GIT_BACKUP_ENABLED=true
OPENDRAFT_GIT_BACKUP_URL=https://gitea.example.com/film/opendraft-backups.git
OPENDRAFT_GIT_BACKUP_ALLOW_INSECURE_HTTP=false
OPENDRAFT_GIT_BACKUP_USERNAME=opendraft-backup
OPENDRAFT_GIT_BACKUP_TOKEN_HOST_FILE=/secure/path/opendraft-gitea-token
OPENDRAFT_GIT_BACKUP_REF_PREFIX=opendraft
# Only for TLS signed by a private CA:
# OPENDRAFT_GIT_BACKUP_CA_BUNDLE_HOST_FILE=/secure/path/ca-bundle.pem
~~~

The deployment script then adds the appropriate secret-file Compose overlay.
The token is read from **/run/secrets/opendraft_gitea_token** for each push,
so it is never placed in an embedded project's Git config. To rotate it,
atomically replace the host token file and rerun **./deploy.sh** (or
**./deploy.sh --combined**) before the next Check In so Compose refreshes the
bind mount.

Every **File -> Versions -> Check In** pushes the project's local HEAD to:

~~~text
refs/heads/opendraft/<user-id>/<project-id>
~~~

Pushes are never forced. A Gitea outage, rejection, or divergent remote branch
does not roll back the local checkpoint; the UI reports that the version is
local-only. Running Check In again, even with no new changes, retries the
backup.

HTTPS is required by default. For a private certificate authority, set
**OPENDRAFT_GIT_BACKUP_CA_BUNDLE_HOST_FILE** to a full CA bundle. The
deployment script mounts it read-only and configures the backend to use it.

After verifying that Gitea and OpenDraft communicate only over an isolated,
trusted local transport, an operator can explicitly set
**OPENDRAFT_GIT_BACKUP_ALLOW_INSECURE_HTTP=true** and use an **http://** URL.
This sends the repository token without transport encryption, so never enable
it for traffic that crosses an untrusted host or network.

## Account deletion and backup retention

Account deletion removes the active authentication record and collaboration
credentials. The backend then makes a best-effort attempt to remove the active
user project directory. A filesystem cleanup failure is logged but does not
recreate the already-deleted account, so an administrator must review the
server logs and remove any reported residual directory manually.

Account deletion does not delete remote Git checkpoint branches, filesystem
snapshots, or off-site backup copies. Those are operator-managed recovery
records and persist until their configured retention period ends or an
administrator explicitly removes them. Document this retention policy for
users who receive accounts.

## What this does not back up

The Gitea mirror contains manual hosted-backend project checkpoints: OpenDraft
JSON, metadata, and project assets. It does not include:

- autosaved changes that have not been checked in;
- live Yjs room files;
- the account/collaboration SQLite database;
- native Tauri SQLite history;
- Fountain, FDX, or PDF exports unless they are added to the project.

Continue snapshotting the complete application state on the storage host and
replicate it off-site. The exact volume set depends on the deployment topology:

- The default source stack requires coordinated snapshots of both
  **demo_data** (projects, assets, and embedded Git history) and
  **collab_data** (accounts, invitations, and Yjs recovery state).
- The combined stack stores both trees in **opendraft_data** under
  **/app/data/backend** and **/app/data/collab**, so snapshot that whole volume.

If these named volumes are backed by separate snapshot-capable datasets,
snapshot them as one consistency group or briefly stop the stack while taking
the snapshots. The Git mirror is a portable second recovery path, not a
replacement for these volume and snapshot backups.
