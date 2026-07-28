/**
 * Birth-warm PrismPipe session cache when a JWT is minted.
 *
 * Product invariant: tokens born via login/register/refresh are never cold on
 * the first client session check — ComputationGraph is populated before the
 * token is returned to the caller.
 */
export async function prewarmPrismSession(token: string): Promise<boolean> {
  const base = (process.env.PRISMPIPE_URL || '').trim().replace(/\/$/, '');
  if (!base) {
    return false;
  }
  const timeoutMs = Number(process.env.PRISMPIPE_PREWARM_TIMEOUT_MS || '2000');
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${base}/pipelines/deepiri/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        authorization: `Bearer ${token}`,
        use_computation_sharing: true,
      }),
      signal: ctrl.signal,
    });
    return res.ok;
  } catch {
    // Login must not fail if PrismPipe is down — session check may be cold once.
    return false;
  } finally {
    clearTimeout(timer);
  }
}
