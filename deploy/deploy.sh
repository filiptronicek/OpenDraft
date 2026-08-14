#!/usr/bin/env bash
set -euo pipefail

# ── OpenDraft VPS Deploy ──
#
# One-shot deploy for demo + collab on a single Ubuntu 22.04 VPS
# (Hostinger KVM 1, Contabo, or any Docker-capable host).
#
# Prereqs on the VPS (run once as root or with sudo):
#   apt update && apt install -y docker.io docker-compose-plugin git
#   systemctl enable --now docker
#
# DNS (free, no domain purchase):
#   1. Sign up at https://www.duckdns.org (GitHub/Google login).
#   2. Create two subdomains, e.g. opendraft + opendraft-collab.
#   3. Point both to this VPS's public IPv4 address.
#
# First run:
#   cd deploy
#   cp .env.example .env
#   # edit .env: set DEMO_HOST, COLLAB_HOST, ACME_EMAIL, JWT_SECRET
#   ./deploy.sh                  # builds backend + collab from source
#   ./deploy.sh --combined       # pulls your configured combined image (no source build)
#
# Update deploy (after git pull or publishing a new image):
#   ./deploy.sh [--combined]

cd "$(dirname "$0")"

# ── Mode selection ──
# --combined (or env OPENDRAFT_USE_COMBINED=1) uses an explicitly configured
# configured single-image build; default is the per-service build-from-source stack.
USE_COMBINED="${OPENDRAFT_USE_COMBINED:-0}"
for arg in "$@"; do
  case "$arg" in
    --combined) USE_COMBINED=1 ;;
    *) echo "Unknown arg: $arg"; exit 1 ;;
  esac
done

if [ "$USE_COMBINED" = "1" ]; then
  COMPOSE_FILE="docker-compose.combined.yml"
  OIDC_COMPOSE_FILE="docker-compose.combined.oidc.yml"
  BACKUP_COMPOSE_FILE="docker-compose.combined.gitea.yml"
  BACKUP_CA_COMPOSE_FILE="docker-compose.combined.gitea-ca.yml"
  MODE_LABEL="combined image (registry pull)"
else
  COMPOSE_FILE="docker-compose.yml"
  OIDC_COMPOSE_FILE="docker-compose.oidc.yml"
  BACKUP_COMPOSE_FILE="docker-compose.gitea.yml"
  BACKUP_CA_COMPOSE_FILE="docker-compose.gitea-ca.yml"
  MODE_LABEL="per-service build"
fi
COMPOSE_ARGS=(-f "$COMPOSE_FILE")

if [ ! -f .env ]; then
  echo "ERROR: .env not found. Copy .env.example to .env and fill it in."
  exit 1
fi

# Pull secrets into the shell so we can validate before handing to compose
set -a
# shellcheck disable=SC1091
source .env
set +a

if [ "$USE_COMBINED" = "1" ]; then
  PUBLIC_UPSTREAM_IMAGE="ghcr.io/proteus-technologies-private-limited/opendraft-combined"
  if [ -z "${OPENDRAFT_IMAGE:-}" ]; then
    echo "ERROR: --combined requires OPENDRAFT_IMAGE to name an image built from this fork."
    echo "The public upstream image does not contain this fork's auth and backup changes."
    exit 1
  fi
  if [ "$OPENDRAFT_IMAGE" = "$PUBLIC_UPSTREAM_IMAGE" ]; then
    echo "ERROR: OPENDRAFT_IMAGE points at the public upstream image."
    echo "Build and publish this fork's Dockerfile.combined, then set its image repository here."
    exit 1
  fi
fi

for var in DEMO_HOST COLLAB_HOST ACME_EMAIL JWT_SECRET CORS_ORIGINS; do
  if [ -z "${!var:-}" ] || [[ "${!var}" == *"change-me"* ]]; then
    echo "ERROR: $var is unset or still the placeholder value in .env"
    exit 1
  fi
done

OIDC_VALUE_COUNT=0
for var in OIDC_ISSUER_URL OIDC_CLIENT_ID OIDC_REDIRECT_URI OIDC_CLIENT_SECRET_HOST_FILE; do
  if [ -n "${!var:-}" ]; then
    OIDC_VALUE_COUNT=$((OIDC_VALUE_COUNT + 1))
  fi
done
if [ "$OIDC_VALUE_COUNT" -ne 0 ]; then
  if [ "$OIDC_VALUE_COUNT" -ne 4 ]; then
    echo "ERROR: OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_REDIRECT_URI, and OIDC_CLIENT_SECRET_HOST_FILE must be configured together"
    exit 1
  fi
  if [ ! -f "$OIDC_CLIENT_SECRET_HOST_FILE" ]; then
    echo "ERROR: OIDC client secret file does not exist: $OIDC_CLIENT_SECRET_HOST_FILE"
    exit 1
  fi
  COMPOSE_ARGS+=(-f "$OIDC_COMPOSE_FILE")
fi

BACKUP_ENABLED="${OPENDRAFT_GIT_BACKUP_ENABLED:-false}"
case "${BACKUP_ENABLED,,}" in
  1|true|yes|on)
    for var in OPENDRAFT_GIT_BACKUP_URL OPENDRAFT_GIT_BACKUP_USERNAME OPENDRAFT_GIT_BACKUP_TOKEN_HOST_FILE; do
      if [ -z "${!var:-}" ]; then
        echo "ERROR: $var is required when Git backup is enabled"
        exit 1
      fi
    done
    if [ ! -f "$OPENDRAFT_GIT_BACKUP_TOKEN_HOST_FILE" ]; then
      echo "ERROR: Gitea token file does not exist: $OPENDRAFT_GIT_BACKUP_TOKEN_HOST_FILE"
      exit 1
    fi
    COMPOSE_ARGS+=(-f "$BACKUP_COMPOSE_FILE")
    if [ -n "${OPENDRAFT_GIT_BACKUP_CA_BUNDLE_HOST_FILE:-}" ]; then
      if [ ! -f "$OPENDRAFT_GIT_BACKUP_CA_BUNDLE_HOST_FILE" ]; then
        echo "ERROR: Gitea CA bundle does not exist: $OPENDRAFT_GIT_BACKUP_CA_BUNDLE_HOST_FILE"
        exit 1
      fi
      COMPOSE_ARGS+=(-f "$BACKUP_CA_COMPOSE_FILE")
    fi
    ;;
  ""|0|false|no|off) ;;
  *)
    echo "ERROR: OPENDRAFT_GIT_BACKUP_ENABLED must be a boolean value"
    exit 1
    ;;
esac

echo "Mode: $MODE_LABEL"
echo "Compose files: ${COMPOSE_ARGS[*]}"
echo

if [ "$USE_COMBINED" = "1" ]; then
  echo "Pulling image (tag: ${OPENDRAFT_VERSION:-latest})..."
  docker compose "${COMPOSE_ARGS[@]}" pull
else
  echo "Building images..."
  docker compose "${COMPOSE_ARGS[@]}" build
fi

echo "Starting stack..."
docker compose "${COMPOSE_ARGS[@]}" up -d

echo ""
echo "Stack status:"
docker compose "${COMPOSE_ARGS[@]}" ps

echo ""
echo "Done. Once DNS has propagated, Caddy will fetch Let's Encrypt certs automatically."
echo "  Demo:   https://${DEMO_HOST}"
echo "  Collab: https://${COLLAB_HOST}  (wss://${COLLAB_HOST} for WebSocket)"
echo ""
echo "Logs:    docker compose ${COMPOSE_ARGS[*]} logs -f"
echo "Restart: docker compose ${COMPOSE_ARGS[*]} restart"
echo "Stop:    docker compose ${COMPOSE_ARGS[*]} down"
