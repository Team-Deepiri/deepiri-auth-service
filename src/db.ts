// Database connection using Prisma
import { PrismaClient } from '@prisma/client';
import { createLogger, secureLog } from '@team-deepiri/shared-utils';

const logger = createLogger('deepiri-auth-service');

// Prisma Client singleton
const prisma = new PrismaClient({
  log: [
    { level: 'query', emit: 'event' },
    { level: 'error', emit: 'event' },
    { level: 'warn', emit: 'event' },
  ],
});

// Log queries in development
if (process.env.NODE_ENV === 'development') {
  prisma.$on('query' as never, (e: any) => {
    logger.debug('Query:', { query: e.query, duration: `${e.duration}ms` });
  });
}

prisma.$on('warn' as never, (event: any) => {
  logger.warn('Prisma warning', {
    message: event.message,
    target: event.target,
  });
});

prisma.$on('error' as never, (event: any) => {
  const message = String(event.message || '');
  const isExpectedRestartInterruption =
    message.includes('terminating connection due to administrator command') ||
    message.includes('SqlState(E57P01)') ||
    message.includes('code: SqlState(E57P01)');

  if (isExpectedRestartInterruption) {
    logger.warn('Prisma connection interrupted during database restart', {
      message,
      target: event.target,
    });
    return;
  }

  logger.error('Prisma client error', {
    message,
    target: event.target,
  });
});

// Connect to database
export async function connectDatabase() {
  try {
    await prisma.$connect();
    secureLog('info', 'Auth Service: Connected to PostgreSQL via Prisma');
  } catch (error) {
    secureLog('error', 'Auth Service: PostgreSQL connection error', error);
    throw error;
  }
}

// Disconnect from database
export async function disconnectDatabase() {
  await prisma.$disconnect();
  secureLog('info', 'Auth Service: Disconnected from PostgreSQL');
}

// Graceful shutdown
process.on('beforeExit', async () => {
  await disconnectDatabase();
});

export default prisma;

