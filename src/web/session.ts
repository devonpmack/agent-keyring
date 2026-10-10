import { timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { hashToken, randomToken } from '../crypto/tokens.js';
import type { AppContext } from '../domain/context.js';
import { addSeconds } from '../domain/context.js';
import { AppError, forbidden } from '../domain/errors.js';
import { getUser, roleIn, type Role, type User } from '../domain/users.js';

const SESSION_TTL = 12 * 60 * 60;
export const RECENT_AUTH_SECONDS = 5 * 60;

export type Session = {
  idHash: string;
  user: User;
  workspaceId: string;
  role: Role;
  csrfToken: string;
  authAt: Date;
  webauthnChallenge: { challenge: string; purpose: string } | null;
};

declare module 'express-serve-static-core' {
  interface Request {
    session?: Session;
  }
}

// __Host- cookies must be Secure, path=/, and host-only, which rules out
// subdomain cookie injection. Plain names are only used for http://localhost dev.
export function cookieNames(ctx: Pick<AppContext, 'config'>) {
  const secure = ctx.config.baseUrl.startsWith('https://');
  return {
    secure,
    session: secure ? '__Host-ak_session' : 'ak_session',
    login: secure ? '__Host-ak_login' : 'ak_login',
  };
}

export function cookieOptions(ctx: Pick<AppContext, 'config'>, maxAgeSeconds: number) {
  return { httpOnly: true, secure: cookieNames(ctx).secure, sameSite: 'lax' as const, path: '/', maxAge: maxAgeSeconds * 1000 };
}

export async function createSession(ctx: AppContext, res: Response, userId: string, workspaceId: string): Promise<void> {
  const token = randomToken('');
  const now = ctx.clock.now();
  await ctx.db.query(
    `insert into sessions (id_hash, user_id, workspace_id, csrf_token, created_at, expires_at, auth_at) values ($1,$2,$3,$4,$5,$6,$5)`,
    [hashToken(token), userId, workspaceId, randomToken('', 24), now, addSeconds(now, SESSION_TTL)],
  );
  res.cookie(cookieNames(ctx).session, token, cookieOptions(ctx, SESSION_TTL));
}

export async function destroySession(ctx: AppContext, req: Request, res: Response): Promise<void> {
  if (req.session) await ctx.db.query('delete from sessions where id_hash = $1', [req.session.idHash]);
  res.clearCookie(cookieNames(ctx).session, { path: '/' });
}

export function loadSession(ctx: AppContext) {
  return async (req: Request, _res: Response, next: NextFunction) => {
    const token: unknown = req.cookies?.[cookieNames(ctx).session];
    if (typeof token !== 'string' || token.length > 100) return next();
    const idHash = hashToken(token);
    const [row] = await ctx.db.query<{ user_id: string; workspace_id: string | null; csrf_token: string; auth_at: Date; expires_at: Date; webauthn_challenge: Session['webauthnChallenge'] }>(
      'select user_id, workspace_id, csrf_token, auth_at, expires_at, webauthn_challenge from sessions where id_hash = $1',
      [idHash],
    );
    if (!row || row.expires_at <= ctx.clock.now() || !row.workspace_id) return next();
    const [user, role] = await Promise.all([getUser(ctx, row.user_id), roleIn(ctx, row.user_id, row.workspace_id)]);
    // Removed from the allowlist: the session stops working immediately.
    if (!user || !role) return next();
    req.session = { idHash, user, workspaceId: row.workspace_id, role, csrfToken: row.csrf_token, authAt: row.auth_at, webauthnChallenge: row.webauthn_challenge };
    next();
  };
}

export function safeReturnTo(value: unknown): string {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) return '/';
  return value.slice(0, 500);
}

export function requireUser(req: Request, res: Response, next: NextFunction): void {
  if (req.session) return next();
  if (req.method === 'GET') return res.redirect(302, `/login?return_to=${encodeURIComponent(safeReturnTo(req.originalUrl))}`);
  next(new AppError('unauthenticated', 'Sign in first', 401));
}

export function requireOwner(req: Request, _res: Response, next: NextFunction): void {
  if (req.session?.role === 'owner') return next();
  next(forbidden('Only the workspace owner can do that'));
}

export function hasRecentAuth(ctx: AppContext, session: Session): boolean {
  return ctx.clock.now().getTime() - session.authAt.getTime() <= RECENT_AUTH_SECONDS * 1000;
}

// Admin actions need a Google sign-in within the last few minutes. GET pages
// bounce through re-auth and come back; a POST with a stale session is refused
// and the form page shows the re-auth prompt.
export function requireRecentAuth(ctx: AppContext) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.session) return next(new AppError('unauthenticated', 'Sign in first', 401));
    if (hasRecentAuth(ctx, req.session)) return next();
    if (req.method === 'GET') return res.redirect(302, `/auth/google?purpose=reauth&return_to=${encodeURIComponent(safeReturnTo(req.originalUrl))}`);
    next(new AppError('reauth_required', 'Confirm it is you: re-authenticate with Google and submit again.', 401));
  };
}

function sameToken(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

// Synchronizer-token CSRF check plus an Origin check for state-changing requests.
export function verifyCsrf(ctx: AppContext) {
  const expectedOrigin = new URL(ctx.config.baseUrl).origin;
  return (req: Request, _res: Response, next: NextFunction) => {
    if (req.method === 'GET' || req.method === 'HEAD') return next();
    const origin = req.get('origin');
    if (origin && origin !== expectedOrigin) return next(forbidden('Cross-origin request refused'));
    const sent = (req.body as Record<string, unknown> | undefined)?._csrf ?? req.get('x-csrf-token');
    if (!req.session || typeof sent !== 'string' || !sameToken(sent, req.session.csrfToken)) {
      return next(forbidden('Your form expired. Reload the page and try again.'));
    }
    next();
  };
}
