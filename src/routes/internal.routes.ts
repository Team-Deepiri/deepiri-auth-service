import { Router, Request, Response, NextFunction } from 'express';
import { PrismaClient } from '@prisma/client';
import { ApiKeyCachePayload } from '@team-deepiri/shared-utils';
import { createRedisClient } from '@team-deepiri/shared-utils';
import { ApiKey } from '../models/ApiKey.model';

const router  = Router();
const prisma  = new PrismaClient();
const redis   = createRedisClient();

const CACHE_TTL_SECONDS = 300;

function requireInternalSecret(
  req:  Request,
  res:  Response,
  next: NextFunction
): void {
  const secret = req.headers['x-internal-secret'] as string | undefined;
  if (!secret || secret !== process.env.INTERNAL_SERVICE_SECRET) {
    console.warn('[AuthService/internal] Rejected — bad or missing internal secret.');
    res.status(403).json({ error: 'Forbidden.' });
    return;
  }
  next();
}

interface ValidateApiKeyRequestBody {
  hashedKey: string;
}

router.post(
  '/validate-api-key',
  requireInternalSecret,
  async (
    req: Request<{}, {}, ValidateApiKeyRequestBody>,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    const { hashedKey } = req.body;

    if (!hashedKey || typeof hashedKey !== 'string') {
      res.status(400).json({ error: 'hashedKey is required in the request body.' });
      return;
    }

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

      console.info(
        `[AuthService/internal] Cache MISS resolved — account: ${payload.serviceAccountId}`
      );

      res.status(200).json(payload);

    } catch (err) {
      console.error('[AuthService/internal] Validation error:', err);
      res.status(503).json({ error: 'Auth service temporarily unavailable.' });
    }
  }
);

export default router;