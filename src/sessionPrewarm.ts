/**
 * Birth-warm PrismPipe session cache when a JWT is minted.
 *
 * Product invariant: tokens born via login/register/refresh are never cold on
 * the first client session check — ComputationGraph is populated before the
 * token is returned to the caller.
 */
import axios from 'axios';
import { logger } from './utils/logger';

/** Stable path constant — not env (pipeline id is part of the PrismPipe contract). */
export const PRISMPIPE_SESSION_PATH = '/pipelines/deepiri/session';

function resolvePrismBaseUrl(): string | null {
  const raw = (process.env.PRISMPIPE_URL || '').trim();
  if (!raw) {
    return null;
  }
  try {
    const url = new URL(raw);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      logger.warn('PRISMPIPE_URL must be http(s); birth-warm disabled', { url: raw });
      return null;
    }
    return url.toString().replace(/\/$/, '');
  } catch {
    logger.warn('PRISMPIPE_URL is not a valid URL; birth-warm disabled', { url: raw });
    return null;
  }
}

function resolvePrewarmTimeoutMs(): number {
  // Keep await short: birth-warm must finish before JWT return, but login UX
  // should not wait multi-seconds when PrismPipe is slow/down.
  const parsed = Number(process.env.PRISMPIPE_PREWARM_TIMEOUT_MS || '800');
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return 800;
  }
  return Math.min(parsed, 2500);
}

export async function prewarmPrismSession(token: string): Promise<boolean> {
  const base = resolvePrismBaseUrl();
  if (!base) {
    return false;
  }
  const timeoutMs = resolvePrewarmTimeoutMs();
  try {
    const res = await axios.post(
      `${base}${PRISMPIPE_SESSION_PATH}`,
      {
        authorization: `Bearer ${token}`,
        use_computation_sharing: true,
      },
      {
        timeout: timeoutMs,
        headers: { 'Content-Type': 'application/json' },
        validateStatus: () => true,
      }
    );
    if (res.status >= 200 && res.status < 300) {
      return true;
    }
    logger.warn('PrismPipe session prewarm non-2xx', {
      status: res.status,
      path: PRISMPIPE_SESSION_PATH,
    });
    return false;
  } catch (err: unknown) {
    // Login must not fail if PrismPipe is down — session check may be cold once.
    const message = err instanceof Error ? err.message : String(err);
    logger.error('PrismPipe session prewarm failed', { error: message });
    return false;
  }
}
