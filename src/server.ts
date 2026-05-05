import express, { Express, Request, Response, ErrorRequestHandler, NextFunction } from 'express';
import { randomUUID } from 'crypto';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import routes from './index';
import { connectDatabase } from './db';
import { bodyParserConfig, requestSizeLimiter } from './middleware/requestLimits';
import { logger } from './utils/logger';

dotenv.config();

const app: Express = express();
const PORT: number = parseInt(process.env.PORT || '5001', 10);

// Middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Parse CORS origins from environment variable (comma-separated)
const corsOrigins = (process.env.CORS_ORIGINS || 'http://localhost:3000,http://localhost:5173,http://127.0.0.1:5173').split(',');

app.use(cors({
  origin: corsOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key', 'x-request-id']
}));

// Request size limits (Issue 8)
app.use(requestSizeLimiter);
app.use(express.json(bodyParserConfig.json));
app.use(express.urlencoded(bodyParserConfig.urlencoded));

// Request ID middleware for correlation tracking
app.use((req: Request, res: Response, next: NextFunction) => {
  const requestId = req.headers['x-request-id'] as string || randomUUID();
  (req as any).requestId = requestId;
  res.setHeader('x-request-id', requestId);
  next();
});

// Request/response logging middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  const startTime = Date.now(); 
  
  res.on('finish', () => {
    const durationMs = Date.now() - startTime;
    logger.info('HTTP request completed', {
      requestId: (req as any).requestId || 'unknown',
      method: req.method,
      path: req.originalUrl,
      statusCode: res.statusCode,
      durationMs,
      userAgent: req.get('user-agent') || 'unknown',
      ip: req.ip,
    });
  });

  next();
});

// PostgreSQL connection via Prisma
connectDatabase()
  .catch((err: Error) => {
    logger.error('Auth Service: Failed to connect to PostgreSQL', { error: err.message, stack: err.stack });
    process.exit(1);
  });

// Routes
app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'healthy', service: 'auth-service', timestamp: new Date().toISOString() });
});

app.use('/', routes);

// Error handler
const errorHandler: ErrorRequestHandler = (err, req, res, next) => {
  logger.error('Unhandled auth service error', {
    requestId: (req as any).requestId || 'unknown',
    method: req.method,
    path: req.originalUrl,
    errorMessage: err instanceof Error ? err.message : 'Unknown error',
    stack: err instanceof Error ? err.stack : undefined,
  });

  res.status(500).json({
    success: false,
    error: 'Internal server error',
    requestId: (req as any).requestId || 'unknown',
    timestamp: new Date().toISOString(),
  });
};
app.use(errorHandler);

app.listen(PORT, () => {
  logger.info(`Auth Service running on port ${PORT}`);
});

export default app;

