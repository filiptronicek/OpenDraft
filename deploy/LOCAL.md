# Local Compose development

Use Colima for the Linux VM and Docker Engine. With Colima installed through Nix:

```sh
colima start --cpu 4 --memory 6 --disk 40
nix shell nixpkgs#docker-client nixpkgs#docker-compose nixpkgs#docker-buildx
```

Run the Docker commands below inside that Nix shell. This does not require
Docker Desktop, OrbStack, or Homebrew Docker plugins.

From the repository root, generate a local signing secret once:

```sh
python3 -c 'import pathlib,secrets; p=pathlib.Path("deploy/.env.local"); p.exists() or p.write_text("JWT_SECRET="+secrets.token_hex(32)+"\n")'
```

Start the application:

```sh
docker --context colima compose --env-file deploy/.env.local -f deploy/compose.local.yml up -d --build
```

Open http://localhost:8080 and register local test accounts. With no SMTP
configured, local registrations are automatically verified. Use separate
browser profiles for simultaneous collaboration tests.

The proxy binds only to localhost. The `opendraft-local` Compose project has
its own project and identity volumes; it does not connect to production
Authentik or Gitea. The signing secret is gitignored. Backend and collaboration
ports are accessible only inside the Compose network.

```sh
# Inspect services and logs
docker --context colima compose --env-file deploy/.env.local -f deploy/compose.local.yml ps
docker --context colima compose --env-file deploy/.env.local -f deploy/compose.local.yml logs --tail=100

# Stop while retaining local accounts and projects
docker --context colima compose --env-file deploy/.env.local -f deploy/compose.local.yml down
```

After code changes, rerun the start command to rebuild the images. This setup
builds the web frontend and both servers from the current checkout.

## Sharing verification

The design is in `docs/design/persistent-collaboration.md`. Register two disposable
local accounts and create a project as the first account, then store their login details in a private JSON file outside the
repository, as an array of two `{ "email": "...", "password": "..." }` objects.
The smoke test targets only `http://localhost:8080`, creates its own screenplay,
and checks discovery, owner-offline editing, saved snapshots, viewer text/metadata
protection, and revocation:

```sh
OPENDRAFT_SMOKE_ACCOUNTS=/path/to/local-accounts.json node deploy/test-sharing.cjs
# Restart collab using the same Compose arguments, then verify persistence:
OPENDRAFT_SMOKE_ACCOUNTS=/path/to/local-accounts.json node deploy/test-sharing.cjs reopen
```

Named sharing is available from an owned screenplay's Invite dialog → People.
Recipients appear after their first OpenDraft sign-in. The Projects page groups
shared screenplays by project and owner. Validated guest links are remembered in
that browser/account until expiry or Forget; named access follows the account.
