import { Router, type Request } from 'express';
import * as oidc from 'openid-client';
import { hashToken, randomToken } from '../crypto/tokens.js';
import type { AppContext } from '../domain/context.js';
import { addSeconds } from '../domain/context.js';
import { AppError } from '../domain/errors.js';
import { signIn } from '../domain/users.js';
import { cookieNames, cookieOptions, createSession, destroySession, RECENT_AUTH_SECONDS, safeReturnTo } from './session.js';

const LOGIN_STATE_TTL = 10 * 60;

export function googleRouter(ctx: AppContext): Router {
  const router = Router();
  let configPromise: Promise<oidc.Configuration> | undefined;
  const oidcConfig = () => {
    configPromise ??= oidc
      .discovery(
        new URL(ctx.config.google.issuer),
        ctx.config.google.clientId,
        ctx.config.google.clientSecret,
        undefined,
        // Only the local mock issuer is plain http.
        ctx.config.google.issuer.startsWith('http://') ? { execute: [oidc.allowInsecureRequests] } : undefined,
      )
      .catch(err => {
        configPromise = undefined;
        throw err;
      });
    return configPromise;
  };
  const redirectUri = `${ctx.config.baseUrl}/auth/callback`;

  router.get('/auth/google', async (req, res, next) => {
    try {
      const purpose = req.query.purpose === 'reauth' ? 'reauth' : 'login';
      if (purpose === 'reauth' && !req.session) return res.redirect(302, '/login');
      const config = await oidcConfig();
      const state = oidc.randomState();
      const nonce = oidc.randomNonce();
      const verifier = oidc.randomPKCECodeVerifier();
      const cookie = randomToken('');
      await ctx.db.query(
        `insert into login_states (id_hash, state, nonce, code_verifier, purpose, return_to, expires_at) values ($1,$2,$3,$4,$5,$6,$7)`,
        [hashToken(cookie), state, nonce, verifier, purpose, safeReturnTo(req.query.return_to), addSeconds(ctx.clock.now(), LOGIN_STATE_TTL)],
      );
      res.cookie(cookieNames(ctx).login, cookie, cookieOptions(ctx, LOGIN_STATE_TTL));
      const params: Record<string, string> = {
        redirect_uri: redirectUri,
        scope: 'openid email profile',
        state,
        nonce,
        code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
        code_challenge_method: 'S256',
        prompt: 'select_account',
      };
      if (purpose === 'reauth') {
        // max_age makes Google re-check the user and return auth_time.
        params.max_age = '0';
        const hint = req.session?.user.email;
        if (hint) params.login_hint = hint;
      }
      res.redirect(302, oidc.buildAuthorizationUrl(config, params).href);
    } catch (err) {
      next(err);
    }
  });

  router.get('/auth/callback', async (req, res, next) => {
    try {
      const cookie: unknown = req.cookies?.[cookieNames(ctx).login];
      res.clearCookie(cookieNames(ctx).login, { path: '/' });
      if (typeof cookie !== 'string') throw new AppError('login_expired', 'Sign-in expired. Try again.');
      const [stateRow] = await ctx.db.query<{ state: string; nonce: string; code_verifier: string; purpose: 'login' | 'reauth'; return_to: string; expires_at: Date }>(
        'delete from login_states where id_hash = $1 returning *',
        [hashToken(cookie)],
      );
      if (!stateRow || stateRow.expires_at <= ctx.clock.now()) throw new AppError('login_expired', 'Sign-in expired. Try again.');

      const config = await oidcConfig();
      const tokens = await oidc.authorizationCodeGrant(config, currentUrl(ctx, req), {
        pkceCodeVerifier: stateRow.code_verifier,
        expectedState: stateRow.state,
        expectedNonce: stateRow.nonce,
        idTokenExpected: true,
      });
      const claims = tokens.claims();
      if (!claims) throw new AppError('login_failed', 'Google did not return an identity');

      if (stateRow.purpose === 'reauth') {
        if (!req.session) throw new AppError('login_expired', 'Your session ended. Sign in again.');
        const [row] = await ctx.db.query<{ google_sub: string }>('select google_sub from users where id = $1', [req.session.user.id]);
        if (row?.google_sub !== claims.sub) throw new AppError('reauth_mismatch', 'Re-authenticate with the same Google account you signed in with.', 403);
        // Google returns auth_time when max_age is requested. Without a fresh one
        // there is no evidence the user re-authenticated, so refuse.
        const authTime = typeof claims.auth_time === 'number' ? claims.auth_time : undefined;
        if (authTime === undefined || ctx.clock.now().getTime() / 1000 - authTime > RECENT_AUTH_SECONDS) {
          throw new AppError('reauth_stale', 'Google did not re-check your sign-in. Sign out of Google in this browser and try again.', 403);
        }
        await ctx.db.query('update sessions set auth_at = $2 where id_hash = $1', [req.session.idHash, ctx.clock.now()]);
        return res.redirect(302, safeReturnTo(stateRow.return_to));
      }

      const { user, workspaceId } = await signIn(
        ctx,
        { sub: claims.sub, email: String(claims.email ?? ''), emailVerified: claims.email_verified === true, name: String(claims.name ?? '') },
        req.ip,
      );
      await destroySession(ctx, req, res);
      await createSession(ctx, res, user.id, workspaceId);
      res.redirect(302, safeReturnTo(stateRow.return_to));
    } catch (err) {
      next(err);
    }
  });

  return router;
}

// openid-client checks the callback URL against redirect_uri, so rebuild it
// from the configured public base URL rather than proxy-supplied headers.
function currentUrl(ctx: AppContext, req: Request): URL {
  return new URL(req.originalUrl, ctx.config.baseUrl);
}
