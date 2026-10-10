import type { AppContext } from './context.js';
import { AppError } from './errors.js';

// Fixed-window counters in Postgres, so limits hold across instances.
export async function hit(
  ctx: Pick<AppContext, 'db' | 'clock'>,
  key: string,
  limit: number,
  windowSeconds: number,
): Promise<void> {
  const now = ctx.clock.now().getTime();
  const windowStart = new Date(now - (now % (windowSeconds * 1000)));
  const [row] = await ctx.db.query<{ count: number }>(
    `insert into rate_limits (key, window_start, count) values ($1, $2, 1)
     on conflict (key, window_start) do update set count = rate_limits.count + 1
     returning count`,
    [key, windowStart],
  );
  if (row && row.count > limit) {
    throw new AppError('rate_limited', 'Too many requests, slow down', 429);
  }
}

export async function pruneRateLimits(ctx: Pick<AppContext, 'db' | 'clock'>): Promise<void> {
  await ctx.db.query('delete from rate_limits where window_start < $1', [new Date(ctx.clock.now().getTime() - 86400_000)]);
}
