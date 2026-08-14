import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import * as crypto from 'crypto';
import { getDB } from '../db';
import type { CollabSessionRow } from '../db';
import { validateInviteToken } from '../services/collabValidation';
import { requireVerifiedAuth } from '../middleware/auth';
import { inviteConnections } from '../services/inviteConnectionRegistry';
import { inviteTokenDigest } from '../services/connectionIdentity';
import { accountLifecycle } from '../services/accountLifecycle';

const router = Router();

const roomSegmentSchema = z.string()
  .trim()
  .min(1)
  .max(128)
  .refine((value) => {
    for (const char of value) {
      const code = char.charCodeAt(0);
      if (char === '/' || char === '\\' || code < 32 || code === 127) return false;
    }
    return true;
  }, 'Invalid room identifier');

export const inviteSchema = z.object({
  project_id: roomSegmentSchema,
  script_id: roomSegmentSchema,
  collaborator_name: z.string().trim().min(1).max(100),
  role: z.enum(['editor', 'viewer']).default('editor'),
  expires_in_hours: z.number().finite().min(0.5).max(720).default(1),
});

/** Generate a URL-safe random token. */
function generateToken(): string {
  return crypto.randomBytes(24).toString('base64url');
}

/** Generate a server-owned session nonce for Yjs room grouping. */
function generateNonce(): string {
  return crypto.randomBytes(16).toString('hex');
}

// ── Create a collaboration invite ────────────────────────────────────────────

router.post('/invite', requireVerifiedAuth, async (req, res) => {
  try {
    const parsed = inviteSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({
        error: 'Invalid input',
        details: parsed.error.flatten().fieldErrors,
      });
      return;
    }
    const {
      project_id,
      script_id,
      collaborator_name,
      role,
      expires_in_hours,
    } = parsed.data;

    const token = generateToken();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + expires_in_hours * 60 * 60 * 1000);
    const createdBy = req.user!.id;
    const creation = await accountLifecycle.runActive(createdBy, async () => {
      const db = getDB();

    // Clients cannot select a room nonce. Reuse only a room already owned by
    // this authenticated user, otherwise mint a fresh unpredictable identity.
    const existing = await db.get<CollabSessionRow>(
      `SELECT session_nonce FROM collab_sessions
       WHERE project_id = ? AND script_id = ? AND created_by = ?
         AND active = 1 AND expires_at > ? AND session_nonce != ''
       ORDER BY created_at DESC LIMIT 1`,
      [project_id, script_id, createdBy, now.toISOString()],
    );
    const nonce = existing?.session_nonce || generateNonce();

    // This owner-checked insert is the cross-process backstop for a deletion
    // racing a request that already passed requireVerifiedAuth.
    const inserted = await db.run(
      `INSERT INTO collab_sessions (token, project_id, script_id, collaborator_name, role, active, session_nonce, created_by, created_at, expires_at)
       SELECT ?, ?, ?, ?, ?, 1, ?, id, ?, ?
       FROM users WHERE id = ?`,
      [
        token,
        project_id,
        script_id,
        collaborator_name,
        role,
        nonce,
        now.toISOString(),
        expiresAt.toISOString(),
        createdBy,
      ],
    );
    if (inserted.changes !== 1) return null;

    return {
      token,
      project_id,
      script_id,
      collaborator_name,
      role,
      active: true,
      session_nonce: nonce,
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
    };
    });

    if (!creation.accepted) {
      res.status(409).json({ error: 'Account deletion is in progress' });
      return;
    }
    if (!creation.value) {
      res.status(401).json({ error: 'Invalid or deleted user' });
      return;
    }
    res.status(201).json(creation.value);
  } catch (err) {
    console.error('Create invite error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Validate a session token ─────────────────────────────────────────────────
// POST keeps the bearer capability out of access-log paths. GET remains only
// for backward compatibility with older clients.

const validateSessionSchema = z.object({
  token: z.string().min(16).max(256),
});

router.post('/session/validate', async (req, res) => {
  const parsed = validateSessionSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid input' });
    return;
  }
  try {
    const session = await validateInviteToken(parsed.data.token);
    if (!session) {
      res.status(404).json({ error: 'Invalid or expired invite' });
      return;
    }
    res.json(session);
  } catch (err) {
    console.error('[collab] POST /session/validate failed:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/session/:token', async (req, res) => {
  const tokenId = inviteTokenDigest(req.params.token).slice(0, 12);
  console.log(`[collab] Legacy GET session validation (invite ${tokenId}) from ${req.ip}`);
  try {
    const session = await validateInviteToken(req.params.token);

    if (!session) {
      console.log(`[collab] Legacy GET session validation (invite ${tokenId}) → 404`);
      res.status(404).json({ error: 'Invalid or expired invite' });
      return;
    }

    console.log(`[collab] Legacy GET session validation (invite ${tokenId}) → 200`);
    res.json(session);
  } catch (err) {
    console.error(`[collab] Legacy GET session validation (invite ${tokenId}) → 500:`, err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── List active sessions for a project/script ────────────────────────────────

router.get('/sessions/:projectId/:scriptId', requireVerifiedAuth, async (req, res) => {
  try {
    const db = getDB();
    const now = new Date().toISOString();

    const sessions = await db.all<CollabSessionRow>(
      `SELECT * FROM collab_sessions
       WHERE project_id = ? AND script_id = ? AND created_by = ? AND active = 1 AND expires_at > ?
       ORDER BY created_at DESC`,
      [req.params.projectId, req.params.scriptId, req.user!.id, now],
    );

    res.json(sessions.map(s => ({
      token: s.token,
      project_id: s.project_id,
      script_id: s.script_id,
      collaborator_name: s.collaborator_name,
      role: s.role,
      active: Boolean(s.active),
      session_nonce: s.session_nonce,
      created_at: s.created_at,
      expires_at: s.expires_at,
    })));
  } catch (err) {
    console.error('List sessions error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Revoke a specific invite ─────────────────────────────────────────────────

async function revokeSessionForOwner(
  req: Request,
  res: Response,
  token: string,
): Promise<void> {
  try {
    const db = getDB();
    const session = await db.get<Pick<CollabSessionRow, 'token' | 'expires_at'>>(
      `SELECT token, expires_at FROM collab_sessions
       WHERE token = ? AND created_by = ? AND active = 1`,
      [token, req.user!.id],
    );
    if (!session) {
      res.status(404).json({ error: 'Session not found' });
      return;
    }
    const result = await db.run(
      'UPDATE collab_sessions SET active = 0 WHERE token = ? AND created_by = ? AND active = 1',
      [token, req.user!.id],
    );
    if (result.changes !== 1) {
      res.status(404).json({ error: 'Session not found' });
      return;
    }
    inviteConnections.closeToken(token, session.expires_at);
    res.json({ message: 'Session revoked' });
  } catch (err) {
    console.error('Revoke session error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
}

// Current clients keep the bearer capability out of proxy/access-log paths.
router.delete('/session', requireVerifiedAuth, async (req, res) => {
  const parsed = validateSessionSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid input' });
    return;
  }
  await revokeSessionForOwner(req, res, parsed.data.token);
});

// Backward compatibility for older clients. New clients use DELETE /session.
router.delete('/session/:token', requireVerifiedAuth, async (req, res) => {
  await revokeSessionForOwner(req, res, String(req.params.token));
});

// ── Revoke all invites for a project/script ──────────────────────────────────

router.delete('/sessions/:projectId/:scriptId', requireVerifiedAuth, async (req, res) => {
  try {
    const db = getDB();
    const sessions = await db.all<Pick<CollabSessionRow, 'token' | 'expires_at'>>(
      'SELECT token, expires_at FROM collab_sessions WHERE project_id = ? AND script_id = ? AND created_by = ? AND active = 1',
      [req.params.projectId, req.params.scriptId, req.user!.id],
    );
    await db.run(
      'UPDATE collab_sessions SET active = 0 WHERE project_id = ? AND script_id = ? AND created_by = ?',
      [req.params.projectId, req.params.scriptId, req.user!.id],
    );
    inviteConnections.closeSessions(sessions);
    res.json({ message: 'All sessions revoked' });
  } catch (err) {
    console.error('Revoke all sessions error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Revoke all invites created by the authenticated user ────────────────────
// Called on logout to clean up all sessions the user created.

router.delete('/my-sessions', requireVerifiedAuth, async (req, res) => {
  try {
    const db = getDB();
    const sessions = await db.all<Pick<CollabSessionRow, 'token' | 'expires_at'>>(
      'SELECT token, expires_at FROM collab_sessions WHERE created_by = ? AND active = 1',
      [req.user!.id],
    );
    const result = await db.run(
      'UPDATE collab_sessions SET active = 0 WHERE created_by = ? AND active = 1',
      [req.user!.id],
    );
    inviteConnections.closeSessions(sessions);
    console.log(`[collab] Revoked all sessions for user ${req.user!.id}`);
    res.json({ message: 'All your sessions revoked', count: (result as any)?.changes || 0 });
  } catch (err) {
    console.error('Revoke my sessions error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
