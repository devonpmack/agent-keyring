import express, { Router } from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import type { OAuthTokenVerifier } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { protectedResourceMetadataUrl } from '../api/rest.js';
import { callerFor } from '../api/caller.js';
import { fetchForAgent, listForAgent, requestApprovalForAgent } from '../domain/access.js';
import type { Caller } from '../domain/approvals.js';
import type { AppContext } from '../domain/context.js';
import { AppError } from '../domain/errors.js';
import type { Grant } from '../domain/grants.js';
import { resourcesOf } from '../oauth/provider.js';

// Read-only by design: there are no tools to create or edit secrets, change a
// policy, or manage grants. Those stay in the human web UI.

const nameField = z.string().describe('Secret path, e.g. "prod/stripe/API_KEY" (folder/name), as returned by list_secrets');
const reasonField = z
  .string()
  .describe('Why you need this secret right now, in one sentence. Shown verbatim to the human who approves the request and recorded in the audit log.');
const requestIdField = z.string().optional().describe('The request_id from an earlier pending_approval response, once the human has approved it');
const totpCodeField = z
  .string()
  .optional()
  .describe('Only for secrets with chat_approval enabled: the 6-digit code the human typed to you, sent with request_id. Never guess or reuse a code.');

function ok(value: unknown): CallToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] };
}

function toolError(err: unknown): CallToolResult {
  if (err instanceof AppError) return { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: err.code, message: err.message }) }] };
  if (err instanceof z.ZodError) return { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: 'invalid_input', message: err.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; ') }) }] };
  console.error(JSON.stringify({ level: 'error', msg: 'mcp tool failed', error: err instanceof Error ? err.name : 'unknown' }));
  return { isError: true, content: [{ type: 'text', text: JSON.stringify({ error: 'server_error', message: 'Internal error' }) }] };
}

async function run(fn: () => Promise<unknown>): Promise<CallToolResult> {
  try {
    return ok(await fn());
  } catch (err) {
    return toolError(err);
  }
}

export function buildMcpServer(ctx: AppContext, caller: Caller, grant: Grant): McpServer {
  const server = new McpServer(
    { name: 'agent-keyring', version: '0.1.0' },
    {
      instructions:
        'agent-keyring holds secrets. Call list_secrets to see what you can access. Secrets with policy "approval" need a human to approve each fetch: ' +
        'get_secret returns pending_approval with an approval_url and request_id; show both to the user, wait for them to approve, then call get_secret again with request_id. ' +
        'Never print secret values back to the user unless they ask, and never store them in files you were not asked to write.',
    },
  );
  const readOnly = { readOnlyHint: true, openWorldHint: false };

  server.registerTool(
    'list_secrets',
    { description: 'List the secrets this agent may use: path, kind, policy, tags, notes. Never returns values.', annotations: readOnly },
    () => run(() => listForAgent(ctx, caller, grant).then(secrets => ({ secrets }))),
  );

  server.registerTool(
    'get_secret',
    {
      description:
        'Fetch a secret. Open secrets return the value. Approval secrets return status "pending_approval" with request_id and approval_url until a human approves; then call again with request_id. TOTP-seed secrets return the current one-time code, never the seed.',
      inputSchema: { name: nameField, reason: reasonField, request_id: requestIdField, totp_code: totpCodeField },
      annotations: readOnly,
    },
    args => run(() => fetchForAgent(ctx, caller, grant, args)),
  );

  server.registerTool(
    'request_approval',
    {
      description: 'Ask a human to approve one future fetch of an approval-policy secret, without fetching yet. Returns request_id and approval_url.',
      inputSchema: { name: nameField, reason: reasonField },
      annotations: readOnly,
    },
    args => run(() => requestApprovalForAgent(ctx, caller, grant, args)),
  );

  server.registerTool(
    'get_totp_code',
    {
      description: 'Get the current 6-digit code for a stored third-party TOTP seed (an MFA secret). Same approval rules as get_secret. The seed itself is never returned.',
      inputSchema: { name: nameField, reason: reasonField, request_id: requestIdField, totp_code: totpCodeField },
      annotations: readOnly,
    },
    args => run(() => fetchForAgent(ctx, caller, grant, args, 'totp')),
  );

  return server;
}

// Stateless streamable HTTP: each POST carries its own bearer token and gets a
// fresh server bound to that token's grant.
export function mcpRouter(ctx: AppContext, verifier: OAuthTokenVerifier): Router {
  const router = Router();
  const resource = resourcesOf(ctx).mcp;
  const auth = requireBearerAuth({ verifier, resourceMetadataUrl: protectedResourceMetadataUrl(resource), expectedResource: new URL(resource) });

  router.post('/mcp', auth, express.json({ limit: '64kb' }), async (req, res) => {
    const { caller, grant } = await callerFor(ctx, req);
    const server = buildMcpServer(ctx, caller, grant);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on('close', () => {
      void transport.close();
      void server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  router.all('/mcp', auth, (_req, res) => {
    res.set('Allow', 'POST').status(405).json({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed' }, id: null });
  });

  return router;
}
