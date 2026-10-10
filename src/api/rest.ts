import express, { Router } from 'express';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import type { OAuthTokenVerifier } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import { fetchForAgent, listForAgent, requestApprovalForAgent } from '../domain/access.js';
import type { AppContext } from '../domain/context.js';
import { resourcesOf } from '../oauth/provider.js';
import { callerFor } from './caller.js';

export function protectedResourceMetadataUrl(resource: string): string {
  const url = new URL(resource);
  return `${url.origin}/.well-known/oauth-protected-resource${url.pathname}`;
}

// REST API for scripts and the CLI. Secret paths contain slashes, so the fetch
// route takes everything between /v1/secrets/ and /fetch.
export function restRouter(ctx: AppContext, verifier: OAuthTokenVerifier): Router {
  const router = Router();
  const resource = resourcesOf(ctx).api;

  router.get('/.well-known/oauth-protected-resource/v1', (_req, res) => {
    res.json({ resource, authorization_servers: [ctx.config.baseUrl], resource_name: 'agent-keyring REST API' });
  });

  const api = Router();
  api.use(requireBearerAuth({ verifier, resourceMetadataUrl: protectedResourceMetadataUrl(resource), expectedResource: new URL(resource) }));
  api.use(express.json({ limit: '16kb' }));

  api.get('/secrets', async (req, res) => {
    const { caller, grant } = await callerFor(ctx, req);
    res.json({ secrets: await listForAgent(ctx, caller, grant) });
  });

  api.post(/^\/secrets\/(.+)\/fetch$/, async (req, res) => {
    const { caller, grant } = await callerFor(ctx, req);
    const result = await fetchForAgent(ctx, caller, grant, { ...req.body, name: decodeURIComponent(String(req.params[0])) });
    res.set('Cache-Control', 'no-store');
    res.status(result.status === 'pending_approval' ? 202 : 200).json(result);
  });

  api.post('/approvals', async (req, res) => {
    const { caller, grant } = await callerFor(ctx, req);
    const result = await requestApprovalForAgent(ctx, caller, grant, { name: req.body?.name, reason: req.body?.reason });
    res.status(result.status === 'pending_approval' ? 202 : 200).json(result);
  });

  router.use('/v1', api);
  return router;
}
