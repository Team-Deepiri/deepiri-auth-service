import * as jwt from 'jsonwebtoken'
import type { JwtPayload } from 'jsonwebtoken'
import { v4 as uuidv4 } from 'uuid'

const ISSUER = 'deepiri-auth-service'
const AUDIENCE = 'deepiri-api'

const JWT_SECRET = process.env.JWT_SECRET
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || (JWT_SECRET ? `${JWT_SECRET}-refresh` : undefined)

const ACCESS_TOKEN_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY || '15m'
const REFRESH_TOKEN_EXPIRY = process.env.REFRESH_TOKEN_EXPIRY || '7d'

function requireSecret(value: string | undefined, name: string): string {
  if (!value) {
    throw new Error(`${name} is not set`)
  }
  // Optional: prevent weak default secrets in prod
  if (process.env.NODE_ENV === 'production' && value.includes('your-secret-key')) {
    throw new Error(`${name} is using an insecure default in production`)
  }
  return value
}

export interface AccessTokenPayload {
  userId: string
  email: string
  roles?: string[]
  iat?: number
  exp?: number
}

export interface RefreshTokenPayload {
  userId: string
  tokenId: string
  iat?: number
  exp?: number
}

/**
 * Sign an access token
 */
export function signAccessToken(payload: {
  userId: string
  email: string
  roles?: string[]
}): string {
  const secret = requireSecret(JWT_SECRET, 'JWT_SECRET')

  return jwt.sign(
    {
      userId: payload.userId,
      email: payload.email,
      roles: payload.roles || ['user'],
    },
    secret,
    {
      expiresIn: ACCESS_TOKEN_EXPIRY,
      issuer: ISSUER,
      audience: AUDIENCE,
    }
  )
}

/**
 * Sign a refresh token
 */
export function signRefreshToken(userId: string): { token: string; tokenId: string } {
  const secret = requireSecret(REFRESH_TOKEN_SECRET, 'REFRESH_TOKEN_SECRET')
  const tokenId = uuidv4()

  const token = jwt.sign(
    { userId, tokenId },
    secret,
    {
      expiresIn: REFRESH_TOKEN_EXPIRY,
      issuer: ISSUER,
      audience: AUDIENCE,
    }
  )

  return { token, tokenId }
}

/**
 * Verify an access token
 */
export function verifyAccessToken(token: string): AccessTokenPayload {
  const secret = requireSecret(JWT_SECRET, 'JWT_SECRET')

  try {
    const decoded = jwt.verify(token, secret, { issuer: ISSUER, audience: AUDIENCE }) as JwtPayload

    if (typeof decoded !== 'object' || !decoded.userId || !decoded.email) {
      throw new Error('Invalid access token')
    }

    return decoded as AccessTokenPayload
  } catch (error: any) {
    if (error?.name === 'TokenExpiredError') throw new Error('Access token expired')
    if (error?.name === 'JsonWebTokenError') throw new Error('Invalid access token')
    throw error
  }
}

/**
 * Verify a refresh token
 */
export function verifyRefreshToken(token: string): RefreshTokenPayload {
  const secret = requireSecret(REFRESH_TOKEN_SECRET, 'REFRESH_TOKEN_SECRET')

  try {
    const decoded = jwt.verify(token, secret, { issuer: ISSUER, audience: AUDIENCE }) as JwtPayload

    if (typeof decoded !== 'object' || !decoded.userId || !decoded.tokenId) {
      throw new Error('Invalid refresh token')
    }

    return decoded as RefreshTokenPayload
  } catch (error: any) {
    if (error?.name === 'TokenExpiredError') throw new Error('Refresh token expired')
    if (error?.name === 'JsonWebTokenError') throw new Error('Invalid refresh token')
    throw error
  }
}

/**
 * Prefer using exp from the signed token (seconds since epoch) when available.
 */
export function getExpirationFromToken(token: string): Date | null {
  const decoded = jwt.decode(token) as JwtPayload | null
  if (!decoded?.exp) return null
  return new Date(decoded.exp * 1000)
}
