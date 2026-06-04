import { Router, Request, Response, NextFunction } from 'express';
import { header, body } from 'express-validator';
import { PrismaClient } from '@prisma/client';
import { ApiKeyCachePayload } from '@team-deepiri/shared-utils';
import { createRedisClient } from '@team-deepiri/shared-utils';
import { validate } from '../middleware/inputValidation';
import { logger } from '../utils/logger';
import { ApiKey } from '../models/ApiKey.model';

const router = Router();
const prisma = new PrismaClient();
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
      const apiKey = await prisma.apiKey.findFirst({
        where: {
          hashedKey,
          revokedAt: null,
          OR: [
            { expiresAt: null },
            { expiresAt: { gt: new Date() } },
          ],
        },
      });

      if (!apiKey) {
        res.status(401).json({ error: 'Invalid, expired, or revoked API key.' });
        return;
      }

      const payload: ApiKeyCachePayload = {
        serviceAccountId: apiKey.id,
        ownerId: apiKey.ownerId,
        scopes: apiKey.scopes as any,
        label: apiKey.label,
      };

      await redis.set(
        `apikey:${hashedKey}`,
        JSON.stringify(payload),
        'EX',
        CACHE_TTL_SECONDS
      );

      try {
        await prisma.apiKey.update({
          where: { id: apiKey.id },
          data: { lastUsedAt: new Date() },
        });
      } catch (updateError) {
        logger.error('[AuthService/internal] Failed to update lastUsedAt', { error: updateError });
      }

      logger.info('[AuthService/internal] Cache MISS resolved');

      res.status(200).json(payload);

    } catch (err) {
      logger.error('[AuthService/internal] Validation error', { error: err });
      res.status(503).json({ error: 'Auth service temporarily unavailable.' });
    }
  }
);

export default router;