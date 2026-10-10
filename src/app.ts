import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import cookieParser from 'cookie-parser';
import express, { type NextFunction, type Request, type Response } from 'express';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { ZodError } from 'zod';
import { restRouter } from './api/rest.js';
import type { AppContext } from './domain/context.js';
import { AppError } from './domain/errors.js';
import { mcpRouter } from './mcp/server.js';
import { KeyringOAuthProvider, resourcesOf } from './oauth/provider.js';
import { googleRouter } from './web/google.js';
import { webRouter } from './web/routes.js';
import { loadSession } from './web/session.js';
import { errorPage } from './web/views.js';

const require = createRequire(import.meta.url);
const staticDir = fileURLToPath(new URL('../static/', import.meta.url));
const webauthnBundle = require.resolve('@simplewebauthn/browser').replace(/esm\/index\.js$|script\/index\.js$/, 'dist/bundle/index.umd.min.js');

function securityHeaders(ctx: AppContext) {
  const https = ctx.config.baseUrl.startsWith('https://');
  return (_req: Request, res: Response, next: NextFunction) => {
    // No form-action: the consent form legitimately redirects to the agent's
    // loopback or custom-scheme redirect URI.
    res.set({
      'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      // same-origin, not no-referrer: with no-referrer, browsers send `Origin: null`
      // on form posts, which the CSRF origin check would refuse.
      'Referrer-Policy': 'same-origin',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    });
    if (https) res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
  };
}

// For a POST refused for a stale session, the page to come back to after re-auth.
function formPageFor(path: string): string {
  if (path === '/secrets') return '/secrets/new';
  if (path.startsWith('/agents/')) return '/agents';
  if (path.startsWith('/members')) return '/members';
  if (path.startsWith('/settings')) return '/settings';
  return path.replace(/\/(delete|revoke|confirm)$/, '');
}

const API_PREFIXES = ['/v1', '/mcp', '/token', '/register', '/revoke', '/authorize', '/.well-known'];

export function createApp(ctx: AppContext): express.Express {
  const app = express();
  app.set('trust proxy', ctx.config.trustProxy);
  app.disable('x-powered-by');
  app.use(securityHeaders(ctx));
  app.use((req, res, next) => {
    res.locals.requestId = randomUUID();
    res.set('X-Request-Id', res.locals.requestId);
    if (!API_PREFIXES.some(p => req.path.startsWith(p))) res.set('Cache-Control', 'no-store');
    next();
  });

  app.get('/healthz', (_req, res) => {
    res.json({ ok: true });
  });
  app.get('/static/vendor/webauthn.js', (_req, res) => res.sendFile(webauthnBundle));
  app.use('/static', express.static(staticDir, { maxAge: '1h', index: false }));

  const provider = new KeyringOAuthProvider(ctx);
  const resources = resourcesOf(ctx);
  app.use(
    mcpAuthRouter({
      provider,
      issuerUrl: new URL(ctx.config.baseUrl),
      resourceServerUrl: new URL(resources.mcp),
      resourceName: 'agent-keyring',
      serviceDocumentationUrl: new URL('https://github.com/devonpmack/agent-keyring'),
    }),
  );
  app.use(mcpRouter(ctx, provider));
  app.use(restRouter(ctx, provider));

  app.use(cookieParser());
  app.use(loadSession(ctx));
  app.use(googleRouter(ctx));
  app.use(webRouter(ctx));

  app.use((req, res) => {
    if (API_PREFIXES.some(p => req.path.startsWith(p))) return res.status(404).json({ error: 'not_found', message: 'Not found' });
    res.status(404).type('html').send(errorPage({ session: req.session }, 404, 'That page does not exist.'));
  });

  app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
    let status = 500;
    let code = 'server_error';
    let message = `Internal error (request ${res.locals.requestId})`;
    if (err instanceof AppError) {
      ({ status, code, message } = err);
    } else if (err instanceof ZodError) {
      status = 400;
      code = 'invalid_input';
      message = err.issues.map(i => (i.path.length ? `${i.path.join('.')}: ${i.message}` : i.message)).join('; ');
    } else if ((err as { type?: string }).type === 'entity.too.large' || (err as { type?: string }).type === 'entity.parse.failed') {
      status = 400;
      code = 'invalid_body';
      message = 'Request body could not be parsed';
    } else {
      // Log the error class and stack only; request bodies may hold secret values.
      console.error(JSON.stringify({ level: 'error', requestId: res.locals.requestId, path: req.path, error: err instanceof Error ? err.stack : String(err) }));
    }
    if (res.headersSent) return;
    const wantsJson = API_PREFIXES.some(p => req.path.startsWith(p)) || req.is('application/json') || req.accepts(['html', 'json']) === 'json';
    if (wantsJson) return res.status(status).json({ error: code, message });
    const reauth = code === 'reauth_required' ? formPageFor(req.path) : undefined;
    res.status(status).type('html').send(errorPage({ session: req.session }, status, message, reauth));
  });

  return app;
}
