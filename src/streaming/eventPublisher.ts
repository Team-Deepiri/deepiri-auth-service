/**
 * Event Publisher for Auth Service.
 *
 * Fires user lifecycle events onto platform-events so other services can react
 * (e.g. engagement service awards welcome momentum on user-registered).
 *
 * All publish functions are fire-and-forget — streaming errors are logged but
 * NEVER propagated so that an unavailable Redis never causes an auth failure.
 */
import { StreamingClient, StreamTopics, StreamEvent, secureLog } from '@deepiri/shared-utils';

let streamingClient: StreamingClient | null = null;

export async function initializeEventPublisher(): Promise<void> {
  try {
    streamingClient = new StreamingClient(
      process.env.REDIS_HOST || 'redis',
      parseInt(process.env.REDIS_PORT || '6379'),
      process.env.REDIS_PASSWORD || 'redispassword'
    );
    await streamingClient.connect();
    secureLog('info', '[Auth] Connected to Redis Streams');
  } catch (error) {
    secureLog('error', '[Auth] Failed to initialize event publisher:', error);
    throw error;
  }
}

async function ensureClient(): Promise<void> {
  if (!streamingClient) {
    await initializeEventPublisher();
  }
}

export async function publishUserRegistered(userId: string, email: string): Promise<void> {
  try {
    await ensureClient();
    const event: StreamEvent = {
      event:     'user-registered',
      timestamp: new Date().toISOString(),
      source:    'auth-service',
      service:   'auth-service',
      user_id:   userId,
      action:    'user-registered',
      data:      { user_id: userId, email },
    };
    await streamingClient!.publish(StreamTopics.PLATFORM_EVENTS, event);
    secureLog('info', `[Auth] Published user-registered event: ${userId}`);
  } catch (error) {
    secureLog('error', '[Auth] Failed to publish user-registered event:', error);
  }
}

export async function publishUserLogin(userId: string): Promise<void> {
  try {
    await ensureClient();
    const event: StreamEvent = {
      event:     'user-login',
      timestamp: new Date().toISOString(),
      source:    'auth-service',
      service:   'auth-service',
      user_id:   userId,
      action:    'user-login',
      data:      { user_id: userId },
    };
    await streamingClient!.publish(StreamTopics.PLATFORM_EVENTS, event);
    secureLog('info', `[Auth] Published user-login event: ${userId}`);
  } catch (error) {
    secureLog('error', '[Auth] Failed to publish user-login event:', error);
  }
}

export async function publishUserLogout(userId: string): Promise<void> {
  try {
    await ensureClient();
    const event: StreamEvent = {
      event:     'user-logout',
      timestamp: new Date().toISOString(),
      source:    'auth-service',
      service:   'auth-service',
      user_id:   userId,
      action:    'user-logout',
      data:      { user_id: userId },
    };
    await streamingClient!.publish(StreamTopics.PLATFORM_EVENTS, event);
    secureLog('info', `[Auth] Published user-logout event: ${userId}`);
  } catch (error) {
    secureLog('error', '[Auth] Failed to publish user-logout event:', error);
  }
}
