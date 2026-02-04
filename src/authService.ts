// src/authService.ts
import type { Request, Response } from 'express'
import bcrypt from 'bcryptjs'
import prisma from './db'

import {
  signAccessToken,
  signRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
} from './utils/jwt'

import {
  saveRefreshToken,
  isRefreshTokenValid,
  revokeRefreshToken,
  revokeAllUserTokens,
  detectTokenTheft
} from './services/refreshTokenService'

class AuthService {
  /**
   * Login
   * - returns accessToken in JSON
   * - stores refreshToken in httpOnly cookie
   * - saves refreshToken in DB
   */
  async login(req: Request, res: Response): Promise<void> {
    try {
      const { email, password } = req.body

      if (!email || !password) {
        res.status(400).json({ error: 'Email and password are required' })
        return
      }

      const user = await prisma.user.findUnique({ where: { email } })
      if (!user) {
        res.status(401).json({ error: 'Invalid credentials' })
        return
      }

      const isValidPassword = await bcrypt.compare(password, user.password)
      if (!isValidPassword) {
        res.status(401).json({ error: 'Invalid credentials' })
        return
      }

      if (!user.isActive) {
        res.status(403).json({ error: 'Account is deactivated' })
        return
      }

      // Update last login
      await prisma.user.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() },
      })

      // Generate tokens
      const accessToken = signAccessToken({
        userId: user.id,
        email: user.email,
      })

      const { token: refreshToken } = signRefreshToken(user.id)

      // Save refresh token to DB
      await saveRefreshToken(
        user.id,
        refreshToken,
        req.ip || undefined,
        req.get('user-agent') || undefined
      )

      // Set refresh token cookie
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days (keep aligned with REFRESH_TOKEN_EXPIRY)
        path: '/api/auth',
      })

      res.json({
        success: true,
        accessToken,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
        },
      })
    } catch (error: any) {
      console.error('Login error:', error)
      res.status(500).json({ error: 'Internal server error' })
    }
  }

  /**
   * Register
   * (kept similar to your old behavior but now also issues refresh cookie)
   */
  async register(req: Request, res: Response): Promise<void> {
    try {
      const { email, password, name } = req.body

      if (!email || !password || !name) {
        res.status(400).json({ error: 'Email, password, and name are required' })
        return
      }

      const existingUser = await prisma.user.findUnique({ where: { email } })
      if (existingUser) {
        res.status(409).json({
          error:
            'An account with this email already exists. Please use a different email or try logging in.',
        })
        return
      }

      const hashedPassword = await bcrypt.hash(password, 10)

      const user = await prisma.user.create({
        data: {
          email,
          password: hashedPassword,
          name,
          isActive: true,
        },
      })

      // Issue tokens (same as login)
      const accessToken = signAccessToken({
        userId: user.id,
        email: user.email,
      })

      const { token: refreshToken } = signRefreshToken(user.id)

      await saveRefreshToken(
        user.id,
        refreshToken,
        req.ip || undefined,
        req.get('user-agent') || undefined
      )

      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000,
        path: '/api/auth',
      })

      res.status(201).json({
        success: true,
        accessToken,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
        },
      })
    } catch (error: any) {
      console.error('Registration error:', error)
      res.status(500).json({ error: 'Internal server error' })
    }
  }

  /**
   * Verify access token (Bearer)
   */
  async verify(req: Request, res: Response): Promise<void> {
    try {
      const authHeader = req.headers.authorization
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({ error: 'No token provided' })
        return
      }

      const token = authHeader.substring(7)
      const decoded = verifyAccessToken(token)

      const user = await prisma.user.findUnique({
        where: { id: decoded.userId },
      })

      if (!user || !user.isActive) {
        res.status(401).json({ error: 'Invalid token' })
        return
      }

      res.json({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
        },
      })
    } catch (error: any) {
      res.status(401).json({ error: 'Invalid token' })
    }
  }

  /**
   * Refresh endpoint (rotation)
   * - takes refreshToken from cookie (preferred) OR req.body.refreshToken
   * - validates JWT + DB record
   * - revokes old refresh token
   * - issues new access + refresh token
   */
  async refresh(req: Request, res: Response): Promise<void> {
  try {
    const refreshToken =
      (req as any).cookies?.refreshToken || req.body?.refreshToken

    if (!refreshToken) {
      res.status(401).json({ error: 'No refresh token provided' })
      return
    }

    // Verify refresh token signature/exp (JWT layer)
    let decoded: { userId: string; tokenId: string }
    try {
      decoded = verifyRefreshToken(refreshToken)
    } catch (error: any) {
      if (error?.message === 'Refresh token expired') {
        res.status(401).json({ error: 'Refresh token expired' })
        return
      }
      res.status(401).json({ error: 'Invalid refresh token' })
      return
    }

    // ✅ PHASE 6: THEFT DETECTION (reuse of a revoked token)
    const theftCheck = await detectTokenTheft(refreshToken)
    if (theftCheck.isTheft) {
      // revoke all tokens for this user (decoded is trustworthy since JWT verified)
      await revokeAllUserTokens(decoded.userId)

      // Clear cookie so client doesn't keep retrying
      res.clearCookie('refreshToken', { path: '/api/auth' })

      console.error('SECURITY ALERT: Refresh token reuse detected', {
        userId: decoded.userId,
        ip: req.ip,
        userAgent: req.get('user-agent'),
      })

      res.status(401).json({
        error: 'Security violation detected. Please log in again.',
      })
      return
    }

    // Normal DB validation (exists, not revoked, not expired, user active)
    const validation = await isRefreshTokenValid(refreshToken)
    if (!validation.valid) {
      res.status(401).json({ error: validation.reason || 'Invalid refresh token' })
      return
    }

    const tokenData = validation.tokenData
    const user = tokenData.user

    // Rotate: revoke old refresh token
    await revokeRefreshToken(refreshToken)

    // Issue new tokens
    const newAccessToken = signAccessToken({
      userId: user.id,
      email: user.email,
    })

    const { token: newRefreshToken } = signRefreshToken(user.id)

    await saveRefreshToken(
      user.id,
      newRefreshToken,
      req.ip || undefined,
      req.get('user-agent') || undefined
    )

    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/api/auth',
    })

    res.json({
      success: true,
      accessToken: newAccessToken,
    })
  } catch (error: any) {
    console.error('Refresh error:', error)
    res.status(401).json({ error: 'Invalid refresh token' })
  }
}


  /**
   * Logout
   * - revoke current refresh token if present
   * - clear refresh cookie
   */
  async logout(req: Request, res: Response): Promise<void> {
  try {
    const refreshToken =
      (req as any).cookies?.refreshToken || req.body?.refreshToken

    if (refreshToken) {
      // Revoke refresh token (best-effort)
      try {
        await revokeRefreshToken(refreshToken)
      } catch {
        // ignore if token not found
      }
    }

    // Clear cookie
    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/api/auth',
    })

    res.json({ success: true, message: 'Logged out successfully' })
  } catch (error: any) {
    console.error('Logout error:', error)
    res.status(500).json({ error: 'Internal server error' })
  }
}


  /**
   * Optional: "logout everywhere" helper (not required, but handy)
   */
  async logoutAll(req: Request, res: Response): Promise<void> {
    try {
      const authHeader = req.headers.authorization
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({ error: 'No token provided' })
        return
      }

      const accessToken = authHeader.substring(7)
      const decoded = verifyAccessToken(accessToken)

      await revokeAllUserTokens(decoded.userId)
      res.clearCookie('refreshToken', { path: '/api/auth' })

      res.json({ success: true, message: 'Logged out from all sessions' })
    } catch (error: any) {
      res.status(401).json({ error: 'Invalid token' })
    }
  }

  async forgotPassword(req: Request, res: Response): Promise<void> {
    // TODO: Implement password reset
    res.status(501).json({ error: 'Not implemented' })
  }

  async resetPassword(req: Request, res: Response): Promise<void> {
    // TODO: Implement password reset
    res.status(501).json({ error: 'Not implemented' })
  }
}

export default new AuthService()
