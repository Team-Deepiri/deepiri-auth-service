import { Router, Request, Response, NextFunction } from 'express';
import { ApiKey } from '../models/ApiKey.model';
import { ApiKeyCachePayload, ApiKeyScope } from 'deepiri-shared-utils/src/types';
import { hashApiKey }        from 'deepiri-shared-utils/src/cryptoUtils';
import { createRedisClient } from 'deepiri-shared-utils/src/redisClient';

const router = Router();
const redis  = createRedisClient();

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
      const apiKeyDoc = await ApiKey.findActiveByHash(hashedKey);

      if (!apiKeyDoc) {
        res.status(401).json({ error: 'Invalid, expired, or revoked API key.' });
        return;
      }

      const payload: ApiKeyCachePayload = apiKeyDoc.toCachePayload();
      const cacheKey = `apikey:${hashedKey}`;

      await redis.set(cacheKey, JSON.stringify(payload), 'EX', CACHE_TTL_SECONDS);

      ApiKey.findByIdAndUpdate(apiKeyDoc._id, { lastUsedAt: new Date() }).exec();

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