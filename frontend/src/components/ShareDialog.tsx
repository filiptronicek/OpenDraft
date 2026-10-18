import PeopleSharing from './PeopleSharing';
import type { SharedDocument } from '../services/sharing';
import React, { useState, useEffect, useRef } from 'react';
import { api } from '../services/api';
import type { CollabSession } from '../services/api';
import { useSettingsStore } from '../stores/settingsStore';
import { collabAuthApi, ensureCollabAuthenticated, COLLAB_AUTH_UNAVAILABLE_MESSAGE } from '../services/collabAuth';
import { getApiBase } from '../config';
import { buildCollabInviteUrl } from '../services/collabInvite';
import { showToast } from './Toast';
import Select from './Select';

interface ShareDialogProps {
  projectId: string;
  scriptId: string;
  scriptTitle: string;
  isCollabActive: boolean;
  onStartCollab: (session: CollabSession) => void;
  onClose: () => void;
  preparePersistent?: () => Promise<SharedDocument>;
}

const EXPIRY_OPTIONS = [
  { label: '30 min', hours: 0.5 },
  { label: '1 hour', hours: 1 },
  { label: '6 hours', hours: 6 },
  { label: '12 hours', hours: 12 },
  { label: '24 hours', hours: 24 },
  { label: '48 hours', hours: 48 },
  { label: '7 days', hours: 168 },
  { label: '30 days', hours: 720 },
];

function formatExpiry(expiresAt: string): string {
  if (!expiresAt) return '';
  const exp = new Date(expiresAt);
  const now = new Date();
  const diffMs = exp.getTime() - now.getTime();
  if (diffMs <= 0) return 'Expired';
  const diffMin = Math.floor(diffMs / 60000);
  if (diffMin < 60) return `${diffMin}m left`;
  const diffHrs = Math.floor(diffMin / 60);
  if (diffHrs < 24) return `${diffHrs}h left`;
  return `${Math.floor(diffHrs / 24)}d left`;
}

const ShareDialog: React.FC<ShareDialogProps> = ({
  projectId,
  scriptId,
  scriptTitle,
  isCollabActive,
  onStartCollab,
  onClose,
  preparePersistent,
}) => {
  const [name, setName] = useState('');
  const [role, setRole] = useState<'editor' | 'viewer'>('editor');
  const [expiryHours, setExpiryHours] = useState(
    useSettingsStore.getState().defaultInviteExpiry || 1,
  );
  const [linksError, setLinksError] = useState('');
  const [linksLoading, setLinksLoading] = useState(true);
  const [sessions, setSessions] = useState<CollabSession[]>([]);
  const [generating, setGenerating] = useState(false);
  const [copiedToken, setCopiedToken] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  // Track whether pointerdown started on the overlay itself (not on the dialog box).
  // On iPad, keyboard dismissal can shift the dialog, causing a synthetic click
  // to land on the overlay even though the user tapped inside the dialog.
  const overlayPointerDown = useRef(false);

  useEffect(() => {
    inputRef.current?.focus();
    let alive = true;
    setLinksLoading(true); setLinksError('');
    api.listCollabSessions(projectId, scriptId)
      .then(s => { if (alive) setSessions(s); })
      .catch(() => { if (alive) setLinksError('Unable to load existing link access. Please reopen Share to retry.'); })
      .finally(() => { if (alive) setLinksLoading(false); });
    return () => { alive = false; };
  }, [projectId, scriptId, isCollabActive]);

  const handleGenerate = async () => {
    const trimmed = name.trim();
    if (!trimmed) return;

    // Verify the user is still signed in, renewing an expired access token
    const authStatus = await ensureCollabAuthenticated();
    if (authStatus === 'unavailable') {
      // Still signed in — keep the dialog open so they can simply retry.
      showToast(COLLAB_AUTH_UNAVAILABLE_MESSAGE, 'error');
      return;
    }
    if (authStatus === 'signed-out') {
      showToast('Session expired — please log in again (Settings → Collaboration)', 'error');
      onClose();
      return;
    }

    setGenerating(true);
    try {
      // Verify the collab server is reachable before creating an invite
      const serverOk = await collabAuthApi.testConnection();
      if (!serverOk) {
        showToast('Cannot reach the collaboration server. Make sure it is running.', 'error');
        setGenerating(false);
        return;
      }

      const session = await api.createCollabInvite(projectId, scriptId, trimmed, role, expiryHours);
      setSessions((prev) => [...prev, session]);
      setName('');
      inputRef.current?.focus();
      showToast(`Invite created for ${trimmed}`, 'success');

      // When first invite is created, start collab for the owner too
      if (!isCollabActive) {
        onStartCollab(session);
      }
    } catch (err) {
      showToast(`Failed to create invite: ${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally {
      setGenerating(false);
    }
  };

  const handleRevoke = async (token: string) => {
    try {
      await api.revokeCollabSession(token);
      setSessions((prev) => prev.filter((s) => s.token !== token));
    } catch {
      showToast('Failed to revoke invite', 'error');
    }
  };

  const handleRevokeAll = async () => {
    try {
      await api.revokeAllCollabSessions(projectId, scriptId);
      setSessions([]);
    } catch {
      showToast('Failed to revoke invites', 'error');
    }
  };

  const copyLink = async (token: string, documentId?: string) => {
    const isTauri = Boolean((window as any).__TAURI_INTERNALS__);
    let link = buildCollabInviteUrl(token, {
      isTauri,
      browserOrigin: window.location.origin,
      apiBase: getApiBase(),
    });
    if (documentId) {
      const url = new URL(link);
      url.pathname = url.pathname.replace(/\/collab$/, `/shared/${encodeURIComponent(documentId)}`);
      url.hash = '';
      link = url.toString();
    }
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(link);
      } else {
        // Fallback for non-secure contexts (HTTP)
        const textarea = document.createElement('textarea');
        textarea.value = link;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      }
      setCopiedToken(token);
      setTimeout(() => setCopiedToken(null), 2000);
    } catch {
      showToast('Failed to copy link to clipboard', 'error');
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && name.trim()) {
      handleGenerate();
    } else if (e.key === 'Escape') {
      onClose();
    }
  };

  return (
    <div
      className="dialog-overlay"
      onPointerDown={(e) => { overlayPointerDown.current = e.target === e.currentTarget; }}
      onClick={(e) => { if (e.target === e.currentTarget && overlayPointerDown.current) onClose(); overlayPointerDown.current = false; }}
    >
      <div
        className="dialog-box"
        style={{ maxWidth: 560 }}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
      >
        <div className="dialog-header">
          Collaborate — {scriptTitle}
        </div>

        <div className="dialog-body">
          {preparePersistent && <PeopleSharing projectId={projectId} scriptId={scriptId} prepare={preparePersistent} />}
          {preparePersistent && <div style={{marginBottom: 20}}>
            <p>Restricted link · Only people with access can open it.</p>
            <button className="dialog-btn" onClick={async () => {
              try { const d = await preparePersistent(); await copyLink('member', d.id); }
              catch (e) { showToast((e as Error).message, 'error'); }
            }}>{copiedToken === 'member' ? 'Copied!' : 'Copy restricted link'}</button>
          </div>}
          <h3>Link access</h3>
          {linksLoading && <p>Loading existing links…</p>}
          {linksError && <p role="alert">{linksError}</p>}
          {sessions.length > 0 && (
            <div className="collab-sessions-list">
              <label className="dialog-label" style={{ fontSize: 14, marginTop: 16 }}>
                Active invites ({sessions.length})
              </label>
              {sessions.map((s) => (
                <div key={s.token} className="collab-session-item">
                  <div className="collab-session-info">
                    <span className="collab-session-name">
                      {s.collaborator_name}
                      <span className={`collab-role-badge collab-role-${s.role || 'editor'}`}>
                        {s.role === 'viewer' ? 'Read Only' : 'Co-Edit'}
                      </span>
                    </span>
                    <span className="collab-session-date">
                      {new Date(s.created_at).toLocaleString()}
                      {s.expires_at && (
                        <span className="collab-session-expiry"> · {formatExpiry(s.expires_at)}</span>
                      )}
                    </span>
                  </div>
                  <div className="collab-session-actions">
                    <button
                      className="collab-copy-btn"
                      onClick={() => copyLink(s.token)}
                      title="Copy invite link"
                      aria-label={
                        copiedToken === s.token
                          ? `Copied invite link for ${s.collaborator_name}`
                          : `Copy invite link for ${s.collaborator_name}`
                      }
                    >
                      {copiedToken === s.token ? 'Copied!' : 'Copy Link'}
                    </button>
                    <button
                      className="collab-revoke-btn"
                      onClick={() => handleRevoke(s.token)}
                      title="Revoke this invite"
                      aria-label={`Revoke invite for ${s.collaborator_name}`}
                    >
                      Revoke
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
          {isCollabActive && (
            <div className="collab-status-badge">
              <span className="collab-dot" /> Live collaboration active
            </div>
          )}

          <p style={{ margin: '0 0 12px', fontSize: 14, color: 'var(--fd-text-muted)' }}>
            Anyone with one of these links can join with its assigned role until it expires.
          </p>

          <label className="dialog-label" style={{ fontSize: 14 }}>Invite a collaborator</label>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              ref={inputRef}
              className="dialog-input"
              style={{ flex: 1 }}
              placeholder="Person's name (e.g., John)"
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={generating}
              aria-label="Collaborator name"
            />
            <button
              className="dialog-btn dialog-btn-primary"
              onClick={handleGenerate}
              disabled={!name.trim() || generating}
            >
              {generating ? 'Creating...' : 'Invite'}
            </button>
          </div>

          {/* Role and expiry options */}
          <div className="collab-invite-options">
            <div className="collab-role-selector">
              <label className="dialog-label" style={{ fontSize: 14, marginTop: 12 }}>Permission</label>
              <div className="collab-role-radios">
                <label className="collab-radio-label">
                  <input
                    type="radio"
                    name="role"
                    value="editor"
                    checked={role === 'editor'}
                    onChange={() => setRole('editor')}
                  />
                  Co-Edit
                </label>
                <label className="collab-radio-label">
                  <input
                    type="radio"
                    name="role"
                    value="viewer"
                    checked={role === 'viewer'}
                    onChange={() => setRole('viewer')}
                  />
                  Read Only
                </label>
              </div>
            </div>

            <div className="collab-expiry-selector">
              <label className="dialog-label" style={{ fontSize: 14, marginTop: 12 }}>Token Valid For</label>
              <Select
                className="dialog-input collab-expiry-select"
                value={expiryHours}
                onChange={(e) => setExpiryHours(Number(e.target.value))}
                aria-label="Invite expiry duration"
              >
                {EXPIRY_OPTIONS.map((opt) => (
                  <option key={opt.hours} value={opt.hours}>
                    {opt.label}
                  </option>
                ))}
              </Select>
            </div>
          </div>

        </div>

        <div className="dialog-footer">
          {sessions.length > 1 && (
            <button
              className="dialog-btn"
              style={{ color: '#e06060' }}
              onClick={handleRevokeAll}
            >
              Revoke All
            </button>
          )}
          <div style={{ flex: 1 }} />
          <button className="dialog-btn" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

export default ShareDialog;
