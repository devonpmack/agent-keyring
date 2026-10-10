import { z } from 'zod';
import {
  approvalUrl,
  approveWithTotp,
  consumeApproval,
  createApprovalRequest,
  effectiveStatus,
  getApprovalForGrant,
  type ApprovalRequest,
  type Caller,
} from './approvals.js';
import { audit } from './audit.js';
import type { AppContext } from './context.js';
import { AppError, notFound } from './errors.js';
import { scopeOf, type Grant } from './grants.js';
import { inScope, joinPath, pathSchema, splitPath } from './paths.js';
import { hit } from './ratelimit.js';
import { decryptSecret, findSecretByPath, listSecrets, type SecretMeta } from './secrets.js';
import { currentCode } from './totp.js';
import { getUser } from './users.js';

// The agent-facing surface, shared by the REST API and the MCP server. Every
// policy decision happens here, server-side: nothing the agent sends can turn
// an `approval` secret into an `open` one.

// Bidi overrides and control characters could make a reason render as
// something other than what was sent; strip them before showing it to a human.
const UNSAFE_CHARS = /[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g;

export const reasonSchema = z
  .string()
  .transform(s => s.replace(UNSAFE_CHARS, ' ').trim())
  .pipe(z.string().min(3, 'reason is required (what you need the secret for)').max(500));

export const fetchInputSchema = z.object({
  name: pathSchema,
  reason: reasonSchema,
  request_id: z.string().regex(/^[0-9A-Z]{10}$/).optional(),
  totp_code: z.string().regex(/^\s*\d{3}\s?\d{3}\s*$/).optional(),
});

export type FetchInput = z.input<typeof fetchInputSchema>;

export type SecretListing = { name: string; folder: string; kind: string; policy: string; tags: string[]; notes: string; chat_approval: boolean };

export type FetchResult =
  | { status: 'ok'; name: string; kind: 'static'; value: string }
  | { status: 'ok'; name: string; kind: 'totp'; code: string; expires_in_seconds: number }
  | {
      status: 'pending_approval';
      name: string;
      request_id: string;
      client: string;
      reason: string;
      expires_at: string;
      approval_url: string;
      instructions: string;
    };

export function callerFromGrant(grant: Grant, clientName: string, ip?: string): Caller {
  return { grantId: grant.id, workspaceId: grant.workspace_id, userId: grant.user_id, clientId: grant.client_id, clientName, ip };
}

function clientActor(caller: Caller) {
  return { type: 'client' as const, id: caller.clientId, label: caller.clientName };
}

export async function listForAgent(ctx: AppContext, caller: Caller, grant: Grant): Promise<SecretListing[]> {
  await hit(ctx, `list:${caller.grantId}`, 60, 60);
  const scope = scopeOf(grant);
  const rows = (await listSecrets(ctx, caller.workspaceId)).filter(s => inScope(scope, s));
  await audit(ctx, { workspaceId: caller.workspaceId, actor: clientActor(caller), action: 'secret.list', outcome: 'success', grantId: caller.grantId, ip: caller.ip, detail: { count: rows.length } });
  return rows.map(s => ({
    name: joinPath(s.folder, s.name),
    folder: s.folder,
    kind: s.kind,
    policy: s.policy,
    tags: s.tags,
    notes: s.notes,
    chat_approval: s.policy === 'approval' && s.allow_chat_approval,
  }));
}

async function resolveInScope(ctx: AppContext, caller: Caller, grant: Grant, path: string): Promise<SecretMeta> {
  const { folder, name } = splitPath(path);
  const secret = await findSecretByPath(ctx, caller.workspaceId, folder, name);
  // Out of scope looks exactly like missing, so a grant cannot probe for names.
  if (!secret || !inScope(scopeOf(grant), secret)) {
    await audit(ctx, { workspaceId: caller.workspaceId, actor: clientActor(caller), action: 'secret.fetch', outcome: 'denied', secretPath: path, grantId: caller.grantId, ip: caller.ip, detail: { why: secret ? 'out_of_scope' : 'not_found' } });
    throw notFound(`No secret named ${path} is available to this agent`);
  }
  return secret;
}

export async function fetchForAgent(ctx: AppContext, caller: Caller, grant: Grant, rawInput: FetchInput, want: 'any' | 'totp' = 'any'): Promise<FetchResult> {
  const input = fetchInputSchema.parse(rawInput);
  await hit(ctx, `fetch:${caller.grantId}`, 60, 60);
  const secret = await resolveInScope(ctx, caller, grant, input.name);
  const path = joinPath(secret.folder, secret.name);
  await hit(ctx, `secret:${secret.id}`, 30, 60);
  if (want === 'totp' && secret.kind !== 'totp_seed') {
    throw new AppError('wrong_kind', `${path} is not a TOTP seed; use get_secret`);
  }
  if (input.totp_code && !input.request_id) {
    throw new AppError('request_id_required', 'A totp_code must be sent together with the request_id it approves');
  }

  if (secret.policy === 'open') return release(ctx, caller, secret, input.reason, undefined);

  if (!input.request_id) {
    const req = await createApprovalRequest(ctx, caller, secret, input.reason);
    return pending(ctx, caller, secret, req);
  }

  const req = await getApprovalForGrant(ctx, caller, input.request_id, secret.id);
  if (!req) throw new AppError('unknown_request', 'That request_id does not belong to this agent and secret', 400);

  let status = effectiveStatus(req, ctx.clock.now());
  if (status === 'pending' && input.totp_code) {
    if (!secret.allow_chat_approval) {
      throw new AppError('chat_approval_disabled', 'This secret only accepts approval on the web page. Ask the human to open the approval URL.', 403);
    }
    // Path (b): the code is checked against the human who connected this agent.
    const approver = await getUser(ctx, caller.userId);
    if (!approver) throw notFound('Approver not found');
    await approveWithTotp(ctx, approver, caller.workspaceId, req.id, input.totp_code, 'totp_chat', caller.ip);
    status = 'approved';
  }

  switch (status) {
    case 'approved':
      if (!(await consumeApproval(ctx, req.id))) throw new AppError('already_used', 'This approval was already used', 409);
      return release(ctx, caller, secret, input.reason, req.id);
    case 'pending':
      return pending(ctx, caller, secret, req);
    case 'denied':
      await audit(ctx, { workspaceId: caller.workspaceId, actor: clientActor(caller), action: 'secret.fetch', outcome: 'denied', secretPath: path, grantId: caller.grantId, approvalId: req.id, reason: input.reason, ip: caller.ip, detail: { why: 'denied' } });
      throw new AppError('denied', 'The human denied this request', 403);
    case 'consumed':
      throw new AppError('already_used', 'This approval was already used; request a new one', 409);
    case 'expired':
      throw new AppError('expired', 'This approval request expired; request a new one', 410);
  }
}

export async function requestApprovalForAgent(ctx: AppContext, caller: Caller, grant: Grant, raw: { name: string; reason: string }): Promise<FetchResult | { status: 'not_required'; name: string }> {
  const input = fetchInputSchema.pick({ name: true, reason: true }).parse(raw);
  const secret = await resolveInScope(ctx, caller, grant, input.name);
  if (secret.policy === 'open') return { status: 'not_required', name: joinPath(secret.folder, secret.name) };
  const req = await createApprovalRequest(ctx, caller, secret, input.reason);
  return pending(ctx, caller, secret, req);
}

function pending(ctx: AppContext, caller: Caller, secret: SecretMeta, req: ApprovalRequest): FetchResult {
  const url = approvalUrl(ctx, req.id);
  const chat = secret.allow_chat_approval
    ? ' Alternatively the human may give you their current 6-digit authenticator code; retry with request_id and totp_code.'
    : '';
  return {
    status: 'pending_approval',
    name: joinPath(secret.folder, secret.name),
    request_id: req.id,
    client: caller.clientName,
    reason: req.reason,
    expires_at: req.expires_at.toISOString(),
    approval_url: url,
    instructions: `A human must approve this. Show them the approval URL and request ID ${req.id}, then retry with request_id once they approve.${chat}`,
  };
}

async function release(ctx: AppContext, caller: Caller, secret: SecretMeta, reason: string, approvalId: string | undefined): Promise<FetchResult> {
  const released = await decryptSecret(ctx, secret);
  const path = joinPath(secret.folder, secret.name);
  await audit(ctx, { workspaceId: caller.workspaceId, actor: clientActor(caller), action: 'secret.fetch', outcome: 'success', secretPath: path, grantId: caller.grantId, approvalId, reason, ip: caller.ip, detail: { kind: secret.kind } });
  if (released.kind === 'totp_seed') {
    const { code, expiresInSeconds } = await currentCode(released.params, ctx.clock.now());
    return { status: 'ok', name: path, kind: 'totp', code, expires_in_seconds: expiresInSeconds };
  }
  return { status: 'ok', name: path, kind: 'static', value: released.value };
}
