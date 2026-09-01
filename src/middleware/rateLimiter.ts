import rateLimit, { Options } from 'express-rate-limit';
import { logger } from '../utils/logger';

// NOTE: the default store is in-memory and therefore PER PROCESS. If auth-service is
// ever run with >1 replica, each replica enforces its own count. Move to
// `rate-limit-redis` (ioredis is already a dependency) before scaling horizontally.

const onLimit: Options['handler'] = (req, res) => {
  logger.warn('Rate limit exceeded', {
    requestId: (req as any).requestId || 'unknown',
    ip: req.ip,
    path: req.originalUrl,
  });
  res.status(429).json({
    success: false,
    error: 'Too many requests, please try again later',
  });
};

const base = {
  standardHeaders: true as const,
  legacyHeaders: false as const,
  handler: onLimit,
  message: { success: false, error: 'Too many requests, please try again later' },
};

/**
 * Lenient limiter for token-lifecycle endpoints that a signed-in SPA calls on a
 * schedule (`/auth/refresh`, the OAuth code/token exchange). High enough that normal
 * app usage never trips it, low enough to blunt a stolen-refresh-token replay.
 * Deliberately NOT applied to `/auth/verify`: that is a read-only token check the
 * frontend calls on load / route change, and rate-limiting it locks users out for a
 * benign call.
 */
export const authRateLimiter = rateLimit({
  ...base,
  windowMs: 15 * 60 * 1000,
  limit: Number(process.env.AUTH_RATE_LIMIT_LENIENT ?? 100),
});

/**
 * Strict limiter for the credential-guessing surface: login, register, and the
 * password-reset request/confirm pair. These are the endpoints rate-limiting exists
 * for; 10 / 15 min / IP stops brute force without inconveniencing a real user.
 */
export const strictAuthRateLimiter = rateLimit({
  ...base,
  windowMs: 15 * 60 * 1000,
  limit: Number(process.env.AUTH_RATE_LIMIT_STRICT ?? 10),
});

// Back-compat default export (was the single 20/15min limiter).
export default authRateLimiter;
