"""Optional, deployment-owned Git backup for hosted OpenDraft projects.

Each embedded project repository is pushed to a separate branch in one
pre-created remote repository. Credentials are read from a mounted secret
file for every push so they never enter a project repository's config.
Container operators must refresh the Compose bind mount after atomically
replacing the host secret file.
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import certifi
import urllib3
from dulwich import porcelain
from dulwich.refs import check_ref_format

logger = logging.getLogger(__name__)

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"", "0", "false", "no", "off"}
_SAFE_COMPONENT = re.compile(r"[^A-Za-z0-9._-]+")


class GitBackupConfigError(ValueError):
    """Raised when an enabled Git backup is unsafe or incomplete."""


@dataclass(frozen=True)
class GitBackupConfig:
    enabled: bool
    remote_url: str
    username: str
    token_file: Path | None
    ref_prefix: str = "opendraft"
    ca_bundle: Path | None = None

    @classmethod
    def from_env(cls) -> "GitBackupConfig":
        enabled_value = os.environ.get(
            "OPENDRAFT_GIT_BACKUP_ENABLED", ""
        ).strip().lower()
        if enabled_value not in _TRUE_VALUES | _FALSE_VALUES:
            raise GitBackupConfigError(
                "OPENDRAFT_GIT_BACKUP_ENABLED must be a boolean value"
            )
        token_file = os.environ.get("OPENDRAFT_GIT_BACKUP_TOKEN_FILE", "").strip()
        ca_bundle = os.environ.get("OPENDRAFT_GIT_BACKUP_CA_BUNDLE", "").strip()
        return cls(
            enabled=enabled_value in _TRUE_VALUES,
            remote_url=os.environ.get("OPENDRAFT_GIT_BACKUP_URL", "").strip(),
            username=os.environ.get("OPENDRAFT_GIT_BACKUP_USERNAME", "").strip(),
            token_file=Path(token_file) if token_file else None,
            ref_prefix=os.environ.get(
                "OPENDRAFT_GIT_BACKUP_REF_PREFIX", "opendraft"
            ).strip(),
            ca_bundle=Path(ca_bundle) if ca_bundle else None,
        )

    def validate(self, *, check_secret: bool = True) -> None:
        """Validate enabled backup configuration without exposing secrets."""
        if not self.enabled:
            return

        parsed = urlsplit(self.remote_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise GitBackupConfigError(
                "OPENDRAFT_GIT_BACKUP_URL must be an absolute HTTPS URL"
            )
        if parsed.username or parsed.password:
            raise GitBackupConfigError(
                "OPENDRAFT_GIT_BACKUP_URL must not contain credentials"
            )
        if parsed.query or parsed.fragment:
            raise GitBackupConfigError(
                "OPENDRAFT_GIT_BACKUP_URL must not contain a query or fragment"
            )
        if not self.username:
            raise GitBackupConfigError(
                "OPENDRAFT_GIT_BACKUP_USERNAME is required when backup is enabled"
            )
        if self.token_file is None or not self.token_file.is_absolute():
            raise GitBackupConfigError(
                "OPENDRAFT_GIT_BACKUP_TOKEN_FILE must be an absolute path"
            )
        if not self.ref_prefix:
            raise GitBackupConfigError(
                "OPENDRAFT_GIT_BACKUP_REF_PREFIX must not be empty"
            )
        try:
            probe_ref = f"refs/heads/{self.ref_prefix}/config-check".encode(
                "ascii", "strict"
            )
        except UnicodeEncodeError as exc:
            raise GitBackupConfigError(
                "OPENDRAFT_GIT_BACKUP_REF_PREFIX must contain ASCII characters"
            ) from exc
        if not check_ref_format(probe_ref):
            raise GitBackupConfigError(
                "OPENDRAFT_GIT_BACKUP_REF_PREFIX is not a valid Git ref prefix"
            )
        if self.ca_bundle is not None:
            if not self.ca_bundle.is_absolute() or not self.ca_bundle.is_file():
                raise GitBackupConfigError(
                    "OPENDRAFT_GIT_BACKUP_CA_BUNDLE must be an absolute readable file"
                )
            try:
                with self.ca_bundle.open("rb") as stream:
                    stream.read(1)
            except OSError as exc:
                raise GitBackupConfigError(
                    "OPENDRAFT_GIT_BACKUP_CA_BUNDLE must be an absolute readable file"
                ) from exc
        if check_secret:
            _read_token(self.token_file)


def _read_token(token_file: Path) -> str:
    try:
        token = token_file.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise GitBackupConfigError(
            "Git backup token file cannot be read"
        ) from exc
    if not token:
        raise GitBackupConfigError("Git backup token file is empty")
    if "\n" in token or "\r" in token:
        raise GitBackupConfigError("Git backup token file must contain one line")
    return token


def _ref_component(value: str) -> str:
    """Return a readable, collision-resistant safe Git ref component."""
    raw = value.strip()
    safe = _SAFE_COMPONENT.sub("-", raw).strip(".-")
    changed = safe != raw or safe.endswith(".lock") or len(safe) > 80
    if not safe:
        safe = "item"
        changed = True
    if changed:
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]
        safe = f"{safe[:68].rstrip('.-') or 'item'}-{digest}"
    return safe


def backup_ref(config: GitBackupConfig, user_id: str, project_id: str) -> str:
    ref = (
        f"refs/heads/{config.ref_prefix}/"
        f"{_ref_component(user_id)}/{_ref_component(project_id)}"
    )
    if not check_ref_format(ref.encode("ascii")):
        raise GitBackupConfigError("Generated Git backup ref is invalid")
    return ref


def validate_startup_config() -> None:
    """Fail startup only for an explicitly enabled, invalid deployment config."""
    GitBackupConfig.from_env().validate(check_secret=True)


def _redact_error(exc: Exception, token: str = "") -> str:
    text = str(exc)
    if token:
        text = text.replace(token, "[REDACTED]")
    text = re.sub(r"https://[^/@\s]+:[^/@\s]+@", "https://[REDACTED]@", text)
    return text[:500]


def push_project(
    project_path: Path,
    user_id: str,
    project_id: str,
    *,
    config: GitBackupConfig | None = None,
) -> dict[str, str | None]:
    """Push a project checkpoint, preserving local success on remote failure."""
    config = config or GitBackupConfig.from_env()
    if not config.enabled:
        return {"status": "disabled", "ref": None, "message": None}

    ref: str | None = None
    token = ""
    try:
        config.validate(check_secret=False)
        assert config.token_file is not None
        token = _read_token(config.token_file)
        ref = backup_ref(config, user_id, project_id)

        ca_file = str(config.ca_bundle) if config.ca_bundle else certifi.where()
        pool = urllib3.PoolManager(
            cert_reqs="CERT_REQUIRED",
            ca_certs=ca_file,
            timeout=urllib3.Timeout(connect=5.0, read=60.0),
            retries=False,
        )
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        result = porcelain.push(
            str(project_path),
            config.remote_url,
            refspecs=[f"HEAD:{ref}"],
            outstream=stdout,
            errstream=stderr,
            force=False,
            username=config.username,
            password=token,
            pool_manager=pool,
        )

        rejected = {
            name.decode("utf-8", errors="replace"): reason
            for name, reason in (result.ref_status or {}).items()
            if reason is not None
        }
        if rejected:
            raise RuntimeError("remote rejected the backup ref update")

        logger.info("Pushed project %s to Git backup ref %s", project_id, ref)
        return {"status": "succeeded", "ref": ref, "message": None}
    except Exception as exc:
        detail = _redact_error(exc, token)
        logger.warning(
            "Git backup failed for project %s (%s): %s",
            project_id,
            type(exc).__name__,
            detail,
        )
        return {
            "status": "failed",
            "ref": ref,
            "message": "Saved locally, but the remote Git backup failed",
        }
