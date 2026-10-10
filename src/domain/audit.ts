import { randomUUID } from 'node:crypto';
import type { Queryable } from '../db/index.js';
import type { AppContext } from './context.js';

// Audit rows record who did what to which secret and why. Callers pass names,
// IDs and the agent's stated reason; values, codes and tokens never go here.
export type AuditEvent = {
  workspaceId: string | null;
  actor: { type: 'user' | 'client' | 'system'; id?: string; label: string };
  action: string;
  outcome: 'success' | 'denied' | 'pending' | 'error';
  secretPath?: string;
  grantId?: string;
  approvalId?: string;
  reason?: string;
  ip?: string;
  detail?: Record<string, unknown>;
};

export async function audit(ctx: Pick<AppContext, 'db' | 'clock'>, e: AuditEvent, q: Queryable = ctx.db): Promise<void> {
  await q.query(
    `insert into audit_events (id, at, workspace_id, actor_type, actor_id, actor_label, action, outcome,
       secret_path, grant_id, approval_id, reason, ip, detail)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
    [
      randomUUID(),
      ctx.clock.now(),
      e.workspaceId,
      e.actor.type,
      e.actor.id ?? null,
      e.actor.label,
      e.action,
      e.outcome,
      e.secretPath ?? null,
      e.grantId ?? null,
      e.approvalId ?? null,
      e.reason ?? null,
      e.ip ?? null,
      JSON.stringify(e.detail ?? {}),
    ],
  );
}

export type AuditRow = {
  id: string;
  at: Date;
  actor_type: string;
  actor_label: string;
  action: string;
  outcome: string;
  secret_path: string | null;
  grant_id: string | null;
  approval_id: string | null;
  reason: string | null;
  ip: string | null;
};

export async function listAudit(
  ctx: Pick<AppContext, 'db'>,
  workspaceId: string,
  filter: { action?: string; secret?: string; grantId?: string; before?: Date; limit?: number },
): Promise<AuditRow[]> {
  const where = ['workspace_id = $1'];
  const params: unknown[] = [workspaceId];
  if (filter.action) {
    params.push(filter.action + '%');
    where.push(`action like $${params.length}`);
  }
  if (filter.secret) {
    params.push(filter.secret);
    where.push(`secret_path = $${params.length}`);
  }
  if (filter.grantId) {
    params.push(filter.grantId);
    where.push(`grant_id = $${params.length}`);
  }
  if (filter.before) {
    params.push(filter.before);
    where.push(`at < $${params.length}`);
  }
  params.push(Math.min(filter.limit ?? 100, 500));
  return ctx.db.query<AuditRow>(
    `select id, at, actor_type, actor_label, action, outcome, secret_path, grant_id, approval_id, reason, ip
     from audit_events where ${where.join(' and ')} order by at desc limit $${params.length}`,
    params,
  );
}
