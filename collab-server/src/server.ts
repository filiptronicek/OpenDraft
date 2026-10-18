import { Hocuspocus } from '@hocuspocus/server';
import type {
  onAuthenticatePayload,
  onConnectPayload,
  onDisconnectPayload,
  connectedPayload,
  beforeHandleMessagePayload,
  onLoadDocumentPayload,
  onStoreDocumentPayload,
  onChangePayload,
} from '@hocuspocus/server';
import * as fs from 'fs';
import * as http from 'http';
import * as https from 'https';
import * as Y from 'yjs';
import express from 'express';
import { z } from 'zod';
import helmet from 'helmet';
import cors from 'cors';
import { WebSocketServer } from 'ws';

import { config } from './config';
import { initDB, getDB } from './db';
import { seedDemoUser } from './bootstrap/seedDemoUser';
import { verifyAccessToken } from './services/tokenService';
import * as auditService from './services/auditService';
import authRoutes from './routes/auth';
import collabRoutes from './routes/collab';
import { standardLimiter } from './middleware/rateLimit';
import { requireVerifiedAuth } from './middleware/auth';
import { documentPath } from './services/documentPath';
import { closeAndAwaitDocumentUnload } from './services/documentLifecycle';
import { compileTrustedProxy, resolveClientIp } from './services/clientIp';
import { connectionLimitKey, inviteTokenDigest } from './services/connectionIdentity';
import { inviteConnections } from './services/inviteConnectionRegistry';
import { applyCollaborationRole } from './services/collaborationAccess';

// ── Data directory for Yjs documents ──
const DATA_DIR = config.dataDir;
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function docPath(documentName: string): string {
  return documentPath(DATA_DIR, documentName);
}

// ── Invite token validation ──
// Extracted to services/collabValidation.ts to avoid circular imports
// (routes/collab.ts also needs it).

import {
  isSessionBoundToDocument,
  parseCanonicalDocumentName,
  validateInviteToken,
} from './services/collabValidation';
import type { CollabSession } from './services/collabValidation';
export { validateInviteToken, type CollabSession };

// ── Connection tracking for WebSocket limits ──

const connectionsPerIp = new Map<string, number>();
const connectionsPerUser = new Map<string, number>();

function incrementCounter(map: Map<string, number>, key: string): number {
  const count = (map.get(key) || 0) + 1;
  map.set(key, count);
  return count;
}

function decrementCounter(map: Map<string, number>, key: string): void {
  const count = (map.get(key) || 1) - 1;
  if (count <= 0) {
    map.delete(key);
  } else {
    map.set(key, count);
  }
}

// ── Document activity tracking for eviction ──

const docLastActivity = new Map<string, number>();
const unavailableDocuments = new Set<string>();
const resettingDocuments = new Set<string>();
const trustedProxy = compileTrustedProxy(config.trustedProxyIps);

function touchDocument(documentName: string): void {
  docLastActivity.set(documentName, Date.now());
}

function startDocumentEviction(): void {
  const timeoutMinutes = config.docIdleTimeoutMinutes;
  if (timeoutMinutes <= 0) {
    console.log('Document eviction: disabled');
    return;
  }

  console.log(`Document eviction: idle documents unloaded after ${timeoutMinutes} minutes`);

  setInterval(() => {
    const now = Date.now();
    const timeoutMs = timeoutMinutes * 60 * 1000;

    for (const [docName, lastActive] of docLastActivity.entries()) {
      if (now - lastActive > timeoutMs) {
        const idleMinutes = Math.round((now - lastActive) / 60_000);
        console.log(`Evicting idle document: ${docName} (idle ${idleMinutes}m)`);
        hocuspocus.closeConnections(docName);
        docLastActivity.delete(docName);
      }
    }
  }, 60 * 1000); // Check every minute
}

// ── Hocuspocus WebSocket server ──

const hocuspocus = new Hocuspocus({
  name: 'OpenDraft Collaboration Server',

  async onAuthenticate(data: onAuthenticatePayload) {
    const rawToken = data.token;
    if (!rawToken) {
      throw new Error('No authentication token provided');
    }
    if (unavailableDocuments.has(data.documentName)) {
      throw new Error('Document is temporarily unavailable');
    }

    let userId: string | null = null;
    let userEmail: string | null = null;
    let inviteToken: string;

    // Parse compound token format: "jwt:<access_token>|invite:<invite_token>"
    if (rawToken.includes('|')) {
      const parts: Record<string, string> = {};
      for (const segment of rawToken.split('|')) {
        const colonIdx = segment.indexOf(':');
        if (colonIdx > 0) {
          parts[segment.slice(0, colonIdx)] = segment.slice(colonIdx + 1);
        }
      }

      // Validate JWT if present — but don't reject if it's expired;
      // the invite token is the primary auth, JWT is supplementary identity
      if (parts.jwt) {
        const jwtPayload = verifyAccessToken(parts.jwt);
        if (jwtPayload) {
          userId = jwtPayload.sub;
          userEmail = jwtPayload.email;
        } else {
          console.warn('JWT expired/invalid — continuing with invite token only');
        }
      }

      inviteToken = parts.invite || '';
    } else {
      // Legacy: plain invite token (backward compatibility)
      inviteToken = rawToken;
    }

    if (!inviteToken) {
      throw new Error('No invite token provided');
    }

    const inviteDigest = inviteTokenDigest(inviteToken);

    // Validate invite token against backend
    const session = await validateInviteToken(inviteToken);
    if (!session) {
      console.error(`[onAuthenticate] Invalid or expired invite ${inviteDigest.slice(0, 12)} for doc: ${data.documentName}`);
      throw new Error('Invalid or expired invite token');
    }
    if (!isSessionBoundToDocument(session, data.documentName)) {
      console.error(`[onAuthenticate] Invite is not valid for document: ${data.documentName}`);
      throw new Error('Invite is not valid for this document');
    }
    if (inviteConnections.isRevoked(inviteDigest)) {
      throw new Error('Invite was revoked during authentication');
    }
    if (unavailableDocuments.has(data.documentName)) {
      throw new Error('Document is temporarily unavailable');
    }

    // Hocuspocus rejects document updates at the protocol boundary when this
    // flag is set. UI editable=false is not an authorization control.
    applyCollaborationRole(data.connectionConfig, session.role);

    // Per-user connection limit check
    const userKey = connectionLimitKey(userId, inviteToken);
    if (config.wsMaxConnectionsPerUser > 0) {
      const userCount = connectionsPerUser.get(userKey) || 0;
      if (userCount >= config.wsMaxConnectionsPerUser) {
        console.warn(`[onAuthenticate] User connection limit reached for: ${userKey} (${userCount}/${config.wsMaxConnectionsPerUser})`);
        throw new Error('Too many connections for this user');
      }
    }
    incrementCounter(connectionsPerUser, userKey);

    // Store session info in the connection context
    data.context.user = {
      id: userId,
      email: userEmail,
      name: session.collaborator_name,
      projectId: session.project_id,
      scriptId: session.script_id,
      role: session.role || 'editor',
      _connKey: userKey, // internal: for tracking disconnections
      _inviteDigest: inviteDigest,
      _inviteExpiresAt: session.expires_at,
    };

    await auditService.logEvent('connect', userId, data.documentName, {
      name: session.collaborator_name,
      role: session.role,
    });
  },

  async onConnect(data: onConnectPayload) {
    const user = data.context?.user;
    console.log(`Client connected to document: ${data.documentName} (${user?.name || 'unknown'}, role: ${user?.role || 'unknown'})`);
    touchDocument(data.documentName);
  },

  async connected(data: connectedPayload) {
    const user = data.context?.user;
    if (user?._inviteDigest) {
      inviteConnections.register(
        data.socketId,
        data.connection,
        user._inviteDigest,
        user._inviteExpiresAt,
      );
    }
  },

  async onDisconnect(data: onDisconnectPayload) {
    inviteConnections.unregister(data.socketId);
    const user = data.context?.user;
    console.log(`Client disconnected from document: ${data.documentName} (${user?.name || 'unknown'})`);

    // Decrement per-user connection counter
    if (user?._connKey) {
      decrementCounter(connectionsPerUser, user._connKey);
    }

    await auditService.logEvent('disconnect', user?.id || null, data.documentName, {
      name: user?.name,
    });
  },

  async beforeHandleMessage(data: beforeHandleMessagePayload) {
    const inviteDigest = data.context?.user?._inviteDigest;
    if (inviteDigest && inviteConnections.isRevoked(inviteDigest)) {
      throw { code: 4403, reason: 'Invite revoked or expired' };
    }
  },

  async onChange(data: onChangePayload) {
    // Viewers may trigger onChange during initial Yjs sync (the Collaboration
    // extension seeds the fragment even with editable:false).  Silently ignore
    // these instead of crashing the server.
    if (data.context?.user?.role === 'viewer') {
      return;
    }
    touchDocument(data.documentName);
  },

  async onLoadDocument(data: onLoadDocumentPayload) {
    const inviteDigest = data.context?.user?._inviteDigest;
    if (inviteDigest && inviteConnections.isRevoked(inviteDigest)) {
      throw new Error('Invite revoked or expired');
    }
    if (unavailableDocuments.has(data.documentName)) {
      throw new Error('Document is temporarily unavailable');
    }
    const filePath = docPath(data.documentName);

    if (fs.existsSync(filePath)) {
      try {
        const binary = fs.readFileSync(filePath);
        const update = new Uint8Array(binary);
        Y.applyUpdate(data.document, update);
        console.log(`Document loaded from disk: ${data.documentName}`);
      } catch (err) {
        console.error(`Failed to load document ${data.documentName}:`, err);
      }
    } else {
      console.log(`New document (no persisted state): ${data.documentName}`);
    }

    touchDocument(data.documentName);
    await auditService.logEvent('document_load', null, data.documentName);
    return data.document;
  },

  async onStoreDocument(data: onStoreDocumentPayload) {
    // Reset deliberately discards this room. Suppress the final close-triggered
    // store, then wait for the store lifecycle to settle before unlinking.
    if (resettingDocuments.has(data.documentName)) {
      return;
    }
    const filePath = docPath(data.documentName);

    try {
      const state = Y.encodeStateAsUpdate(data.document);
      fs.writeFileSync(filePath, Buffer.from(state));
      console.log(`Document stored: ${data.documentName}`);
    } catch (err) {
      console.error(`Failed to store document ${data.documentName}:`, err);
    }

    await auditService.logEvent('document_store', null, data.documentName);
  },
});

// ── Express app for REST API ──

const app = express();

// HTTP and WebSocket paths share the same explicit proxy trust boundary.
// Never trust X-Forwarded-For merely because NODE_ENV is production.
app.set('trust proxy', trustedProxy);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (e.g. curl, Tauri, mobile apps)
    if (!origin) return callback(null, true);

    // Allow explicitly configured origins
    if (config.corsOrigins.includes(origin)) return callback(null, true);

    // Allow any private/local network origin (192.168.*, 10.*, 172.16-31.*, localhost, 127.*)
    try {
      const url = new URL(origin);
      const host = url.hostname;
      if (
        host === 'localhost' ||
        host.startsWith('127.') ||
        host.startsWith('10.') ||
        host.startsWith('192.168.') ||
        /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
        host === '::1' ||
        host === 'tauri.localhost'
      ) {
        return callback(null, true);
      }
    } catch { /* invalid URL, fall through to reject */ }

    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));
app.use(express.json());

// Request logger — logs all incoming HTTP requests
app.use((req, _res, next) => {
  const safePath = req.path.replace(
    /^\/api\/collab\/session\/[^/]+$/,
    '/api/collab/session/[REDACTED]',
  );
  console.log(`[http] ${req.method} ${safePath} from ${req.ip} origin=${req.headers.origin || 'none'}`);
  next();
});

app.use(standardLimiter);

// Auth routes
app.use('/auth', authRoutes);

// Collab invite management (create, validate, list, revoke)
// Used by both Tauri desktop/mobile clients and the web frontend.
app.use('/api/collab', collabRoutes);

// Health check with memory & connection stats
app.get('/health', (_req, res) => {
  const mem = process.memoryUsage();
  const totalWsConnections = Array.from(connectionsPerIp.values()).reduce((a, b) => a + b, 0);

  res.json({
    status: 'ok',
    service: 'opendraft-collab',
    uptime: Math.round(process.uptime()),
    database: config.dbType,
    memory: {
      rss_mb: Math.round(mem.rss / 1024 / 1024),
      heap_used_mb: Math.round(mem.heapUsed / 1024 / 1024),
      heap_total_mb: Math.round(mem.heapTotal / 1024 / 1024),
      external_mb: Math.round(mem.external / 1024 / 1024),
    },
    documents: {
      tracked: docLastActivity.size,
    },
    connections: {
      total: totalWsConnections,
      unique_ips: connectionsPerIp.size,
      unique_users: connectionsPerUser.size,
    },
  });
});

const resetDocumentSchema = z.object({
  documentName: z.string().min(1).max(400),
  token: z.string().min(16).max(256),
});
const closeDocumentSchema = z.object({
  documentName: z.string().min(1).max(400),
});

async function userOwnsDocument(
  userId: string,
  documentName: string,
  token?: string,
  activeOnly = false,
): Promise<boolean> {
  const room = parseCanonicalDocumentName(documentName);
  if (!room) return false;

  const params: unknown[] = [room.projectId, room.scriptId, room.sessionNonce, userId];
  let sql = `SELECT token FROM collab_sessions
    WHERE project_id = ? AND script_id = ? AND session_nonce = ? AND created_by = ?`;
  if (token) {
    sql += ' AND token = ?';
    params.push(token);
  }
  if (activeOnly) {
    sql += ' AND active = 1 AND expires_at > ?';
    params.push(new Date().toISOString());
  }
  sql += ' LIMIT 1';
  return Boolean(await getDB().get<{ token: string }>(sql, params));
}

app.post('/api/reset-document', requireVerifiedAuth, async (req, res) => {
  try {
    const parsed = resetDocumentSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid input' });
      return;
    }
    const { documentName, token } = parsed.data;
    if (!(await userOwnsDocument(req.user!.id, documentName, token, true))) {
      res.status(403).json({ error: 'Not authorized to reset this document' });
      return;
    }

    if (unavailableDocuments.has(documentName)) {
      res.status(409).json({ error: 'Document operation already in progress' });
      return;
    }

    unavailableDocuments.add(documentName);
    resettingDocuments.add(documentName);
    try {
      const unloaded = await closeAndAwaitDocumentUnload(hocuspocus, documentName);
      if (!unloaded) {
        res.status(503).json({ error: 'Document did not close in time; reset was not applied' });
        return;
      }

      const filePath = docPath(documentName);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
      docLastActivity.delete(documentName);
      res.json({ status: 'ok' });
    } finally {
      resettingDocuments.delete(documentName);
      unavailableDocuments.delete(documentName);
    }
  } catch (err) {
    console.error('Reset document error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/close-document', requireVerifiedAuth, async (req, res) => {
  try {
    const parsed = closeDocumentSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Invalid input' });
      return;
    }
    const { documentName } = parsed.data;
    if (!(await userOwnsDocument(req.user!.id, documentName))) {
      res.status(403).json({ error: 'Not authorized to close this document' });
      return;
    }
    if (unavailableDocuments.has(documentName)) {
      res.status(409).json({ error: 'Document operation already in progress' });
      return;
    }

    unavailableDocuments.add(documentName);
    try {
      const unloaded = await closeAndAwaitDocumentUnload(hocuspocus, documentName);
      if (!unloaded) {
        res.status(503).json({ error: 'Document did not close in time' });
        return;
      }
      console.log(`Document closed and unloaded: ${documentName}`);
      // Retain final Yjs state as recovery data; new sessions use new nonces.
      docLastActivity.delete(documentName);
      res.json({ status: 'ok' });
    } finally {
      unavailableDocuments.delete(documentName);
    }
  } catch (err) {
    console.error('Close document error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Bootstrap: init DB then start HTTP(S) server ──

async function main(): Promise<void> {
  // Initialize database (async — needed for PostgreSQL)
  await initDB();
  // Seed the demo user once the schema exists. No-op unless SEED_DEMO_USER is set.
  await seedDemoUser();

  const HOST = config.host;
  const PORT = config.port;
  let httpServer: http.Server | https.Server;

  if (config.tlsCert && config.tlsKey) {
    const cert = fs.readFileSync(config.tlsCert);
    const key = fs.readFileSync(config.tlsKey);
    httpServer = https.createServer({ cert, key }, app);
    console.log('TLS enabled (wss://)');
  } else {
    httpServer = http.createServer(app);
    console.log('TLS disabled (ws://)');
  }

  // WebSocket server (noServer mode — we handle upgrade manually)
  const wss = new WebSocketServer({ noServer: true });

  httpServer.on('upgrade', (request, socket, head) => {
    // Per-IP connection limit check
    const ip = resolveClientIp(request, trustedProxy);
    if (config.wsMaxConnectionsPerIp > 0) {
      const ipCount = connectionsPerIp.get(ip) || 0;
      if (ipCount >= config.wsMaxConnectionsPerIp) {
        console.warn(`[upgrade] IP connection limit reached for: ${ip} (${ipCount}/${config.wsMaxConnectionsPerIp})`);
        socket.write('HTTP/1.1 429 Too Many Requests\r\n\r\n');
        socket.destroy();
        return;
      }
    }

    wss.handleUpgrade(request, socket, head, (ws) => {
      incrementCounter(connectionsPerIp, ip);

      ws.on('close', () => {
        decrementCounter(connectionsPerIp, ip);
      });

      // Pass the upgraded WebSocket connection to Hocuspocus
      hocuspocus.handleConnection(ws, request);
    });
  });

  // Start document eviction timer
  startDocumentEviction();
  const inviteExpirySweep = setInterval(() => {
    inviteConnections.closeExpired();
  }, 30_000);
  inviteExpirySweep.unref();

  httpServer.listen(PORT, HOST, () => {
    const protocol = config.tlsCert ? 'wss' : 'ws';
    console.log(`OpenDraft Collaboration Server running on ${HOST}:${PORT}`);
    console.log(`  WebSocket: ${protocol}://${HOST}:${PORT}`);
    console.log(`  REST API:  ${config.tlsCert ? 'https' : 'http'}://${HOST}:${PORT}`);
    console.log(`  Proxies:   ${config.trustedProxyIps.join(', ')}`);
    console.log(`  Database:  ${config.dbType}`);
    console.log(`  WS limits: ${config.wsMaxConnectionsPerIp}/IP, ${config.wsMaxConnectionsPerUser}/user`);
  });
}

main().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
