// JWT authentication + role gate for the portal /users routes.
//
// The gateway forwards the client's `Authorization: Bearer <jwt>` header
// untouched, so this service verifies the token itself (same JWT_SECRET as
// authService) and loads the user fresh from the DB — the token's `role` claim
// can be up to 7 days stale, so authorization decisions use the live column.

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import prisma from '../db';
import { validateSecret } from '@team-deepiri/shared-utils';

// validateSecret returns the value or throws — a missing/short/weak JWT_SECRET
// fails the service at startup rather than falling back to a usable key.
const JWT_SECRET = validateSecret('JWT_SECRET', process.env.JWT_SECRET, 32);

export interface AuthedUser {
  id: string;
  email: string;
  name: string;
  role: string;
}

export interface AuthedRequest extends Request {
  authUser?: AuthedUser;
}

export async function authenticate(req: Request, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'No token provided' });
    return;
  }

  // Token problems -> 401. Kept narrow so a DB failure below can't masquerade
  // as an auth failure.
  let decoded: { userId?: string };
  try {
    decoded = jwt.verify(authHeader.substring(7), JWT_SECRET) as { userId?: string };
  } catch {
    res.status(401).json({ error: 'Invalid token' });
    return;
  }
  if (!decoded?.userId) {
    res.status(401).json({ error: 'Invalid token' });
    return;
  }

  try {
    const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
    if (!user) {
      res.status(401).json({ error: 'Invalid token' });
      return;
    }
    if (user.status !== 'active') {
      res.status(403).json({ error: 'Account is not active' });
      return;
    }

    (req as AuthedRequest).authUser = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
    };
    next();
  } catch (err) {
    console.error('authenticate: user lookup failed', err);
    res.status(500).json({ error: 'Internal server error' });
  }
}

// Route guard. Must run after `authenticate`.
export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const authUser = (req as AuthedRequest).authUser;
    if (!authUser) {
      res.status(401).json({ error: 'Unauthenticated' });
      return;
    }
    if (!roles.includes(authUser.role)) {
      res.status(403).json({ error: 'Insufficient role' });
      return;
    }
    next();
  };
}
