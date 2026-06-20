import { Router, Request, Response, NextFunction } from 'express';
import { header, body } from 'express-validator';
import { ApiKeyCachePayload } from '@team-deepiri/shared-utils';
import { createRedisClient } from '@team-deepiri/shared-utils';
import { ApiKey } from '../models/ApiKey.model';
import { validate } from '../middleware/inputValidation';
import { logger } from '../utils/logger';

const router = Router();
const redis = createRedisClient();
const CACHE_TTL_SECONDS = 300;

interface ValidateApiKeyRequestBody {
  hashedKey: string;
}

router.post(
  '/validate-api-key',
  validate([
    header('x-internal-secret')
      .trim()
      .notEmpty()
      .withMessage('x-internal-secret header is required')
      .custom((secretValue: string) => {
        if (!process.env.INTERNAL_SERVICE_SECRET || secretValue !== process.env.INTERNAL_SERVICE_SECRET) {
          throw new Error('Invalid internal service secret');
        }
        return true;
      }),
    body('hashedKey')
      .trim()
      .notEmpty()
      .withMessage('hashedKey is required in the request body.')
      .isLength({ min: 16, max: 512 })
      .withMessage('hashedKey must be between 16 and 512 characters long'),
  ], {
    allowedBodyFields: ['hashedKey'],
    allowedHeaderFields: ['x-internal-secret', 'x-request-id', 'x-api-key'],
  }),
  async (
    req: Request<{}, {}, ValidateApiKeyRequestBody>,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    const { hashedKey } = req.body;

    try {
      const apiKey = await ApiKey.findActiveByHash(hashedKey);

      if (!apiKey) {
        res.status(401).json({ error: 'Invalid, expired, or revoked API key.' });
        return;
      }

      const payload: ApiKeyCachePayload = apiKey.toCachePayload();

      await redis.set(
        `apikey:${hashedKey}`,
        JSON.stringify(payload),
        'EX',
        CACHE_TTL_SECONDS
      );

      apiKey.lastUsedAt = new Date();
      apiKey.save().catch(console.error);

      logger.info('[AuthService/internal] Cache MISS resolved');

      res.status(200).json(payload);

    } catch (err) {
      logger.error('[AuthService/internal] Validation error', { error: err });
      res.status(503).json({ error: 'Auth service temporarily unavailable.' });
    }
  }
);

export default router;