import React, { useState, useRef, useEffect } from 'react';
import { api } from '../services/api';
import type { CollabSession } from '../services/api';
import { getApiBase, getCollabWsUrl } from '../config';
import { platformFetch } from '../services/platform';
import { parseCollabInvite } from '../services/collabInvite';
import { showToast } from './Toast';

interface JoinCollabDialogProps {
  onJoin: (session: CollabSession, token: string, collabServerUrl?: string) => void;
  onClose: () => void;
}

const JoinCollabDialog: React.FC<JoinCollabDialogProps> = ({ onJoin, onClose }) => {
  const [linkInput, setLinkInput] = useState('');
  const [joining, setJoining] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleJoin = async () => {
    const configuredCollabUrl = getCollabWsUrl();
    const { token, collabServerUrl } = parseCollabInvite(linkInput, {
      configuredCollabUrl,
      frontendBaseUrls: [window.location.origin, getApiBase()],
    });
    console.log('[JoinCollab] Parsed invite transport:', collabServerUrl || 'configured');
    if (!token) {
      showToast('Please paste a collaboration link or token', 'error');
      return;
    }

    setJoining(true);
    try {
      let session: CollabSession | null = null;

      // Use the collab server URL extracted from the invite link if available,
      // otherwise fall back to the local setting.
      const wsUrl = collabServerUrl || configuredCollabUrl;
      const collabHttpUrl = wsUrl.replace(/^wss:/, 'https:').replace(/^ws:/, 'http:');
      console.log('[JoinCollab] Step 1: trying collab server at', collabHttpUrl);
      try {
        const res = await platformFetch(`${collabHttpUrl}/api/collab/session/validate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token }),
        });
        console.log('[JoinCollab] Step 1 response:', res.status);
        if (res.ok) {
          session = await res.json();
          console.log('[JoinCollab] Step 1 session found:', session?.project_id);
        } else {
          const errBody = await res.text().catch(() => '');
          console.warn('[JoinCollab] Step 1 failed:', res.status, errBody);
        }
      } catch (err) {
        console.error('[JoinCollab] Step 1 error (collab server unreachable):', err);
      }

      // Fall back to the local backend
      if (!session) {
        console.log('[JoinCollab] Step 2: falling back to api.validateCollabSession');
        try {
          session = await api.validateCollabSession(token);
          console.log('[JoinCollab] Step 2 session found:', session?.project_id);
        } catch (err) {
          console.error('[JoinCollab] Step 2 failed:', err);
          throw err;
        }
      }

      onJoin(session, token, collabServerUrl || undefined);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error('[JoinCollab] All attempts failed:', msg);
      showToast(`Failed to join: ${msg}`, 'error');
    } finally {
      setJoining(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && linkInput.trim()) {
      handleJoin();
    } else if (e.key === 'Escape') {
      onClose();
    }
  };

  return (
    <div className="dialog-overlay" onClick={onClose}>
      <div
        className="dialog-box"
        style={{ maxWidth: 500 }}
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
      >
        <div className="dialog-header">
          Join Collaboration Session
        </div>

        <div className="dialog-body">
          <p style={{ margin: '0 0 16px', fontSize: 14, color: 'var(--fd-text-muted)' }}>
            Paste the collaboration link or token you received from the session host.
          </p>

          <div className="settings-field">
            <label>Collaboration Link or Token</label>
            <input
              ref={inputRef}
              className="dialog-input"
              style={{ fontSize: 14, height: 40, padding: '0 12px' }}
              value={linkInput}
              onChange={(e) => setLinkInput(e.target.value)}
              placeholder="https://example.com/collab/... or paste token"
              disabled={joining}
            />
          </div>
        </div>

        <div className="dialog-footer">
          <div style={{ flex: 1 }} />
          <button className="dialog-btn" onClick={onClose}>Cancel</button>
          <button
            className="dialog-btn dialog-btn-primary"
            style={{ background: 'var(--fd-accent)', color: '#fff', border: 'none', fontWeight: 600 }}
            onClick={handleJoin}
            disabled={!linkInput.trim() || joining}
          >
            {joining ? 'Joining...' : 'Join Session'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default JoinCollabDialog;
