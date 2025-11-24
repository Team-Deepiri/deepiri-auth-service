import express, { Express, Request, Response, ErrorRequestHandler } from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import winston from 'winston';
import routes from './index';

dotenv.config();

const app: Express = express();
const PORT: number = parseInt(process.env.PORT || '5001', 10);

// Logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.Console({ format: winston.format.simple() })
  ]
});

// Middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));
app.use(cors({
  origin: ['http://localhost:5173', 'http://localhost:3000', 'http://127.0.0.1:5173'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key']
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Debug middleware to log incoming requests
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path}`, {
    headers: req.headers,
    bodyExists: !!req.body,
    bodyKeys: req.body ? Object.keys(req.body) : []
  });
  next();
});

// MongoDB connection
const MONGO_URI: string = process.env.MONGO_URI || 'mongodb://mongodb:27017/deepiri';
mongoose.connect(MONGO_URI)
  .then(() => logger.info('Auth Service: Connected to MongoDB'))
  .catch((err: Error) => logger.error('Auth Service: MongoDB connection error', err));

// Routes
app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'healthy', service: 'auth-service', timestamp: new Date().toISOString() });
});

app.use('/', routes);

// Error handler
const errorHandler: ErrorRequestHandler = (err, req, res, next) => {
  logger.error('Auth Service error:', err);
  res.status(500).json({ error: 'Internal server error' });
};
app.use(errorHandler);

app.listen(PORT, () => {
  logger.info(`Auth Service running on port ${PORT}`);
});

export default app;

