// Portal user directory + profile + role management.
// Mounted in src/index.ts under /users, behind the `authenticate` middleware.

import { Request, Response } from 'express';
import prisma from './db';
import { AuthedRequest } from './middleware/auth';

// --- Role model -------------------------------------------------------------
// Team roles a user may pick for themselves (onboarding / PUT /users/profile).
const TEAM_ROLES = ['ai_ml', 'qa_support', 'software_developer', 'it'] as const;
const SELF_ASSIGNABLE = new Set<string>(TEAM_ROLES);
// Extra roles an admin may grant to other people via PUT /users/:id/role.
const ADMIN_GRANTABLE = new Set<string>([...TEAM_ROLES, 'leadership']);
// Extra roles an owner may grant. 'owner' is never grantable over the API.
const OWNER_GRANTABLE = new Set<string>([...TEAM_ROLES, 'leadership', 'admin']);

// Authority order for the directory sort (most senior first).
const ROLE_RANK: Record<string, number> = {
  owner: 0, leadership: 1, admin: 2, it: 3,
  ai_ml: 4, software_developer: 5, qa_support: 6, member: 7,
};
const rankOf = (role?: string | null) => ROLE_RANK[role ?? 'member'] ?? 99;

// Fields safe to return for any authenticated caller. Never `password`.
const PUBLIC_USER_SELECT = {
  id: true, name: true, email: true, avatarUrl: true, bio: true,
  role: true, status: true, metadata: true, createdAt: true, lastLoginAt: true,
};

type MetadataObject = Record<string, unknown>;

function mergeMetadata(existing: unknown, incoming: unknown): MetadataObject {
  const base: MetadataObject =
    existing && typeof existing === 'object' && !Array.isArray(existing)
      ? { ...(existing as MetadataObject) }
      : {};
  if (incoming && typeof incoming === 'object' && !Array.isArray(incoming)) {
    for (const [k, v] of Object.entries(incoming as MetadataObject)) base[k] = v;
  }
  // Role is a first-class column — never let it ride along inside the JSON blob.
  delete base.role;
  delete base.deepiriRole;
  return base;
}

class UsersService {
  // GET /users — org directory, ordered by authority then name.
  async list(_req: Request, res: Response): Promise<void> {
    try {
      const users = await prisma.user.findMany({ select: PUBLIC_USER_SELECT });
      users.sort((a, b) => rankOf(a.role) - rankOf(b.role) || (a.name || '').localeCompare(b.name || ''));
      res.json({ success: true, users });
    } catch (error) {
      console.error('List users error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  // GET /users/profile — the caller's own record.
  async getProfile(req: Request, res: Response): Promise<void> {
    try {
      const authUser = (req as AuthedRequest).authUser!;
      const user = await prisma.user.findUnique({
        where: { id: authUser.id },
        select: PUBLIC_USER_SELECT,
      });
      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }
      res.json({ success: true, user });
    } catch (error) {
      console.error('Get profile error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  // PUT /users/profile — self-service profile edit. A `role` here is only
  // honoured when it's a team role; leadership/admin/owner are rejected and must
  // go through PUT /users/:id/role.
  async updateProfile(req: Request, res: Response): Promise<void> {
    try {
      const authUser = (req as AuthedRequest).authUser!;
      const { name, email, avatarUrl, bio, metadata, role } = req.body as {
        name?: string; email?: string; avatarUrl?: string; bio?: string;
        metadata?: unknown; role?: string;
      };

      if (role !== undefined && !SELF_ASSIGNABLE.has(role)) {
        res.status(403).json({ error: 'That role must be assigned by an administrator' });
        return;
      }

      const current = await prisma.user.findUnique({ where: { id: authUser.id } });
      if (!current) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      const data: Record<string, unknown> = {};
      if (typeof name === 'string' && name.trim()) data.name = name.trim();
      if (typeof avatarUrl === 'string') data.avatarUrl = avatarUrl || null;
      if (typeof bio === 'string') data.bio = bio;
      if (role !== undefined) data.role = role;
      if (metadata !== undefined) data.metadata = mergeMetadata(current.metadata, metadata);

      if (typeof email === 'string' && email.trim() && email.trim().toLowerCase() !== current.email.toLowerCase()) {
        const normalized = email.trim().toLowerCase();
        const clash = await prisma.user.findUnique({ where: { email: normalized } });
        if (clash && clash.id !== current.id) {
          res.status(409).json({ error: 'An account with this email already exists' });
          return;
        }
        data.email = normalized;
      }

      const user = await prisma.user.update({
        where: { id: authUser.id },
        data: data as any,
        select: PUBLIC_USER_SELECT,
      });
      res.json({ success: true, user });
    } catch (error) {
      console.error('Update profile error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }

  // PUT /users/:id/role — grant/change another user's role.
  // Route is already gated to owner|admin by requireRole().
  async setRole(req: Request, res: Response): Promise<void> {
    try {
      const actor = (req as AuthedRequest).authUser!;
      const targetId = req.params.id;
      const nextRole = String((req.body as { role?: string }).role || '');

      const grantable = actor.role === 'owner' ? OWNER_GRANTABLE : ADMIN_GRANTABLE;
      if (!grantable.has(nextRole)) {
        res.status(403).json({ error: `You cannot assign the role "${nextRole || '(none)'}"` });
        return;
      }

      if (targetId === actor.id) {
        res.status(403).json({ error: 'You cannot change your own role' });
        return;
      }

      const target = await prisma.user.findUnique({ where: { id: targetId } });
      if (!target) {
        res.status(404).json({ error: 'User not found' });
        return;
      }
      if (target.role === 'owner') {
        res.status(403).json({ error: 'An owner\'s role cannot be changed here' });
        return;
      }
      if (target.role === 'admin' && actor.role !== 'owner') {
        res.status(403).json({ error: 'Only an owner can change an admin' });
        return;
      }
      if (target.role === nextRole) {
        const { password, ...safe } = target;
        res.json({ success: true, user: safe });
        return;
      }

      const user = await prisma.user.update({
        where: { id: targetId },
        data: { role: nextRole, updatedBy: actor.id },
        select: PUBLIC_USER_SELECT,
      });
      console.info(`[roles] ${actor.email} (${actor.role}) set ${target.email}: ${target.role} -> ${nextRole}`);
      res.json({ success: true, user });
    } catch (error) {
      console.error('Set role error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
}

export default new UsersService();
