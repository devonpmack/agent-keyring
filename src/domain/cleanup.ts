import type { AppContext } from './context.js';
import { pruneRateLimits } from './ratelimit.js';

// Expired rows carry no value once past their deadline; approval requests and
// audit events are kept as history.
export async function cleanupExpired(ctx: AppContext): Promise<void> {
  const now = ctx.clock.now();
  await pruneRateLimits(ctx);
  await ctx.db.query('delete from login_states where expires_at < $1', [now]);
  await ctx.db.query('delete from oauth_authorizations where expires_at < $1', [now]);
  await ctx.db.query('delete from oauth_codes where expires_at < $1', [now]);
  await ctx.db.query('delete from sessions where expires_at < $1', [now]);
  await ctx.db.query('delete from oauth_tokens where expires_at < $1', [now]);
}
