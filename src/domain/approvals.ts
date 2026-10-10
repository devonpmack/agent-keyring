import { humanId } from '../crypto/tokens.js';
import { audit } from './audit.js';
import type { AppContext } from './context.js';
import { addSeconds } from './context.js';
import { AppError, forbidden, notFound } from './errors.js';
import { joinPath } from './paths.js';
import { hit } from './ratelimit.js';
import type { SecretMeta } from './secrets.js';
import { verifyUserCode } from './totp.js';
import type { User } from './users.js';
import { roleIn } from './users.js';

export const APPROVAL_TTL_SECONDS = 5 * 60;
const MAX_ATTEMPTS_PER_REQUEST = 5;

export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'consumed' | 'expired';
export type DecisionMethod = 'totp_web' | 'totp_chat' | 'passkey' | 'deny' | 'secret_changed';

export type ApprovalRequest = {
  id: string;
  workspace_id: string;
  secret_id: string;
  grant_id: string;
  reason: string;
  status: Exclude<ApprovalStatus, 'expired'>;
  created_at: Date;
  expires_at: Date;
  decided_at: Date | null;
  decided_by: string | null;
  decision_method: DecisionMethod | null;
  failed_attempts: number;
};

export type Caller = { grantId: string; workspaceId: string; userId: string; clientId: string; clientName: string; ip?: string };

export function effectiveStatus(req: Pick<ApprovalRequest, 'status' | 'expires_at'>, now: Date): ApprovalStatus {
  if ((req.status === 'pending' || req.status === 'approved') && req.expires_at <= now) return 'expired';
  return req.status;
}

export function approvalUrl(ctx: Pick<AppContext, 'config'>, id: string): string {
  return `${ctx.config.baseUrl}/approvals/${id}`;
}

export async function createApprovalRequest(ctx: AppContext, caller: Caller, secret: SecretMeta, reason: string): Promise<ApprovalRequest> {
  await hit(ctx, `approval:${caller.grantId}`, 10, 600);
  const now = ctx.clock.now();
  const id = humanId(10);
  const [row] = await ctx.db.query<ApprovalRequest>(
    `insert into approval_requests (id, workspace_id, secret_id, grant_id, reason, status, created_at, expires_at)
     values ($1,$2,$3,$4,$5,'pending',$6,$7) returning *`,
    [id, caller.workspaceId, secret.id, caller.grantId, reason, now, addSeconds(now, APPROVAL_TTL_SECONDS)],
  );
  const path = joinPath(secret.folder, secret.name);
  await audit(ctx, {
    workspaceId: caller.workspaceId,
    actor: { type: 'client', id: caller.clientId, label: caller.clientName },
    action: 'approval.request',
    outcome: 'pending',
    secretPath: path,
    grantId: caller.grantId,
    approvalId: id,
    reason,
    ip: caller.ip,
  });
  await ctx.notifier.notify({ type: 'approval_requested', workspaceId: caller.workspaceId, approvalId: id, secretPath: path, clientName: caller.clientName, reason, url: approvalUrl(ctx, id) });
  return row!;
}

export async function getApprovalForGrant(ctx: Pick<AppContext, 'db'>, caller: Caller, id: string, secretId: string): Promise<ApprovalRequest | undefined> {
  const [row] = await ctx.db.query<ApprovalRequest>(
    'select * from approval_requests where id = $1 and workspace_id = $2 and grant_id = $3 and secret_id = $4',
    [id, caller.workspaceId, caller.grantId, secretId],
  );
  return row;
}

// Single use: only one fetch can flip approved -> consumed.
export async function consumeApproval(ctx: AppContext, id: string): Promise<boolean> {
  const now = ctx.clock.now();
  const rows = await ctx.db.query(
    `update approval_requests set status = 'consumed', consumed_at = $2
     where id = $1 and status = 'approved' and expires_at > $2 returning id`,
    [id, now],
  );
  return rows.length === 1;
}

export type ApprovalView = ApprovalRequest & {
  effective_status: ApprovalStatus;
  secret_path: string;
  secret_kind: string;
  client_id: string;
  client_name: string;
  client_first_seen: Date;
  grant_label: string;
  grant_owner_email: string;
  decided_by_email: string | null;
};

export async function getApprovalView(ctx: Pick<AppContext, 'db' | 'clock'>, workspaceId: string, id: string): Promise<ApprovalView> {
  const [row] = await ctx.db.query<Omit<ApprovalView, 'effective_status' | 'secret_path'> & { folder: string; name: string }>(
    `select r.*, s.folder, s.name, s.kind as secret_kind, g.client_id, c.metadata->>'client_name' as client_name,
       c.created_at as client_first_seen, g.label as grant_label, u.email as grant_owner_email, d.email as decided_by_email
     from approval_requests r
     join secrets s on s.id = r.secret_id
     join grants g on g.id = r.grant_id
     join oauth_clients c on c.client_id = g.client_id
     join users u on u.id = g.user_id
     left join users d on d.id = r.decided_by
     where r.workspace_id = $1 and r.id = $2`,
    [workspaceId, id],
  );
  if (!row) throw notFound('Approval request not found');
  const { folder, name, ...rest } = row;
  return {
    ...rest,
    client_name: rest.client_name || `Unnamed client ${rest.client_id.slice(0, 8)}`,
    secret_path: joinPath(folder, name),
    effective_status: effectiveStatus(row, ctx.clock.now()),
  };
}

export async function listApprovals(ctx: Pick<AppContext, 'db' | 'clock'>, workspaceId: string, limit = 50): Promise<ApprovalView[]> {
  const ids = await ctx.db.query<{ id: string }>(
    'select id from approval_requests where workspace_id = $1 order by created_at desc limit $2',
    [workspaceId, limit],
  );
  return Promise.all(ids.map(r => getApprovalView(ctx, workspaceId, r.id)));
}

async function requireApprover(ctx: AppContext, user: User, workspaceId: string): Promise<void> {
  if (!(await roleIn(ctx, user.id, workspaceId))) throw forbidden();
}

function assertPending(view: ApprovalView): void {
  const status = view.effective_status;
  if (status === 'expired') throw new AppError('expired', 'This request has expired. Ask the agent to request it again.', 410);
  if (status !== 'pending') throw new AppError('not_pending', `This request is already ${status}.`, 409);
}

async function markApproved(ctx: AppContext, approver: User, view: ApprovalView, method: DecisionMethod, ip?: string): Promise<void> {
  const now = ctx.clock.now();
  const rows = await ctx.db.query(
    `update approval_requests set status = 'approved', decided_at = $2, decided_by = $3, decision_method = $4, expires_at = $5
     where id = $1 and status = 'pending' and expires_at > $2 returning id`,
    [view.id, now, approver.id, method, addSeconds(now, APPROVAL_TTL_SECONDS)],
  );
  if (rows.length !== 1) throw new AppError('not_pending', 'This request is no longer pending.', 409);
  await audit(ctx, {
    workspaceId: view.workspace_id,
    actor: { type: 'user', id: approver.id, label: approver.email },
    action: 'approval.approve',
    outcome: 'success',
    secretPath: view.secret_path,
    grantId: view.grant_id,
    approvalId: view.id,
    reason: view.reason,
    ip,
    detail: { method },
  });
}

// Shared by the web page (path a) and the agent retry with totp_code (path b).
export async function approveWithTotp(ctx: AppContext, approver: User, workspaceId: string, id: string, code: string, method: 'totp_web' | 'totp_chat', ip?: string): Promise<void> {
  await requireApprover(ctx, approver, workspaceId);
  const view = await getApprovalView(ctx, workspaceId, id);
  assertPending(view);
  const check = await verifyUserCode(ctx, approver.id, code, workspaceId);
  if (check.ok) return markApproved(ctx, approver, view, method, ip);

  const [row] = await ctx.db.query<{ failed_attempts: number }>(
    `update approval_requests set failed_attempts = failed_attempts + 1,
       status = case when failed_attempts + 1 >= $2 then 'denied' else status end,
       decision_method = case when failed_attempts + 1 >= $2 then 'deny' else decision_method end
     where id = $1 and status = 'pending' returning failed_attempts`,
    [id, MAX_ATTEMPTS_PER_REQUEST],
  );
  await audit(ctx, {
    workspaceId,
    actor: { type: 'user', id: approver.id, label: approver.email },
    action: 'approval.code_rejected',
    outcome: 'denied',
    secretPath: view.secret_path,
    grantId: view.grant_id,
    approvalId: id,
    ip,
    detail: { method, locked: check.locked, attempts: row?.failed_attempts },
  });
  if (check.locked) throw new AppError('locked', 'Too many wrong codes. Approvals are locked for 15 minutes.', 423);
  throw new AppError('invalid_code', 'That code is wrong or was already used. Wait for the next code and try again.', 400);
}

export async function approveWithPasskey(ctx: AppContext, approver: User, workspaceId: string, id: string, ip?: string): Promise<void> {
  await requireApprover(ctx, approver, workspaceId);
  const view = await getApprovalView(ctx, workspaceId, id);
  assertPending(view);
  await markApproved(ctx, approver, view, 'passkey', ip);
}

export async function denyApproval(ctx: AppContext, user: User, workspaceId: string, id: string, ip?: string): Promise<void> {
  await requireApprover(ctx, user, workspaceId);
  const view = await getApprovalView(ctx, workspaceId, id);
  assertPending(view);
  const now = ctx.clock.now();
  await ctx.db.query(
    `update approval_requests set status = 'denied', decided_at = $2, decided_by = $3, decision_method = 'deny' where id = $1 and status = 'pending'`,
    [id, now, user.id],
  );
  await audit(ctx, {
    workspaceId,
    actor: { type: 'user', id: user.id, label: user.email },
    action: 'approval.deny',
    outcome: 'success',
    secretPath: view.secret_path,
    grantId: view.grant_id,
    approvalId: id,
    reason: view.reason,
    ip,
  });
}
