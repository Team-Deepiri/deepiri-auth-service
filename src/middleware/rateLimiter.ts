import rateLimit from 'express-rate-limit';
import { logger } from '../utils/logger';

const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many requests, please try again later',
  },
  handler: (req, res, next) => {
    logger.warn('Rate limit exceeded', {
      requestId: (req as any).requestId || 'unknown',
      ip: req.ip,
      path: req.originalUrl,
    });
    res.status(429).json({
      success: false,
      error: 'Too many requests, please try again later',
    });
  },
});

export default authRateLimiter;
