import type { Request, Response, NextFunction } from 'express';
import { verifyAccessToken } from '../services/tokenService';
import { getDB } from '../db';

export interface AuthUser {
  id: string;
  email: string;
  displayName: string;
  emailVerified: boolean;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

export async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  const token = authHeader.slice(7);
  const payload = verifyAccessToken(token);
  if (!payload) {
    res.status(401).json({ error: 'Invalid or expired token' });
    return;
  }

  let currentUser: {
    id: string;
    email: string;
    display_name: string;
    email_verified: number;
  } | undefined;
  try {
    currentUser = await getDB().get(
      'SELECT id, email, display_name, email_verified FROM users WHERE id = ?',
      [payload.sub],
    );
  } catch {
    res.status(503).json({ error: 'Authentication store unavailable' });
    return;
  }
  if (!currentUser) {
    res.status(401).json({ error: 'Invalid or deleted user' });
    return;
  }

  req.user = {
    id: currentUser.id,
    email: currentUser.email,
    displayName: currentUser.display_name,
    emailVerified: Boolean(currentUser.email_verified),
  };
  next();
}

export async function requireVerifiedAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  await requireAuth(req, res, () => {
    if (!req.user?.emailVerified) {
      res.status(403).json({
        detail: {
          error: 'email_not_verified',
          message: 'Verify your email to continue',
        },
      });
      return;
    }
    next();
  });
}

export function optionalAuth(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    const payload = verifyAccessToken(token);
    if (payload) {
      req.user = {
        id: payload.sub,
        email: payload.email,
        displayName: payload.name,
        emailVerified: payload.email_verified,
      };
    }
  }
  next();
}
