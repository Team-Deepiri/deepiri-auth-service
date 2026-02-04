import prisma from '../db';
import { getExpirationFromToken } from '../utils/jwt'


/**
 * Save a refresh token to the database
 */
export async function saveRefreshToken(
  userId: string,
  token: string,
  ipAddress?: string,
  userAgent?: string
) {
  const expiresAt = getExpirationFromToken(token);
  if (!expiresAt) throw new Error('Refresh token missing exp claim');

  return prisma.refreshToken.create({
    data: {
      userId,
      token,
      expiresAt,
      ipAddress,
      userAgent,
    },
  });
}


/**
 * Find a refresh token by token string
 */
export async function findRefreshToken(token: string) {
  return prisma.refreshToken.findUnique({
    where: { token },
    include: {
      user: {
        select: {
          id: true,
          email: true,
          name: true,
          isActive: true,
        },
      },
    },
  });
}

/**
 * Revoke a refresh token
 */
export async function revokeRefreshToken(token: string) {
  return prisma.refreshToken.update({
    where: { token },
    data: {
      revoked: true,
      revokedAt: new Date(),
    },
  });
}

/**
 * Revoke all refresh tokens for a user
 */
export async function revokeAllUserTokens(userId: string) {
  return prisma.refreshToken.updateMany({
    where: {
      userId,
      revoked: false,
    },
    data: {
      revoked: true,
      revokedAt: new Date(),
    },
  });
}

/**
 * Delete expired refresh tokens (cleanup job)
 */
export async function deleteExpiredTokens() {
  return prisma.refreshToken.deleteMany({
    where: {
      expiresAt: {
        lt: new Date(),
      },
    },
  });
}

/**
 * Check if refresh token is valid
 */
export async function isRefreshTokenValid(token: string): Promise<{
  valid: boolean;
  reason?: string;
  tokenData?: any;
}> {
  const tokenData = await findRefreshToken(token);

  if (!tokenData) {
    return { valid: false, reason: 'Token not found' };
  }

  if (tokenData.revoked) {
    return { valid: false, reason: 'Token revoked' };
  }

  if (tokenData.expiresAt < new Date()) {
    return { valid: false, reason: 'Token expired' };
  }

  if (!tokenData.user.isActive) {
    return { valid: false, reason: 'User inactive' };
  }

  return { valid: true, tokenData };
}

// src/services/refreshTokenService.ts
export async function detectTokenTheft(token: string): Promise<{
  isTheft: boolean
  shouldRevokeAll: boolean
  userId?: string
}> {
  const tokenData = await prisma.refreshToken.findUnique({
    where: { token },
    select: {
      revoked: true,
      userId: true,
    },
  })

  // Not found: could be random/invalid token. Not "reuse" theft by itself.
  if (!tokenData) {
    return { isTheft: false, shouldRevokeAll: false }
  }

  // If it exists AND is revoked, that means it was already rotated or logged out.
  // Using it again is refresh-token reuse => theft / replay.
  if (tokenData.revoked) {
    return { isTheft: true, shouldRevokeAll: true, userId: tokenData.userId }
  }

  return { isTheft: false, shouldRevokeAll: false, userId: tokenData.userId }
}
