import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { hashToken, randomToken } from '../crypto/tokens.js';
import { audit } from '../domain/audit.js';
import type { AppContext } from '../domain/context.js';
import { addSeconds } from '../domain/context.js';
import { AppError, forbidden, notFound } from '../domain/errors.js';
import { clientDisplayName, redirectHost, type ClientMetadata } from '../domain/grants.js';
import { describeScope, folderSchema, pathSchema, tagSchema } from '../domain/paths.js';
import type { User } from '../domain/users.js';
import { roleIn } from '../domain/users.js';

const CODE_TTL = 60;

export type PendingAuthorization = {
  id: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  state: string | null;
  resource: string;
  expires_at: Date;
  client_name: string;
  redirect_host: string;
  client_first_seen: Date;
  previously_granted: boolean;
};

export async function getAuthorization(ctx: Pick<AppContext, 'db' | 'clock'>, id: string): Promise<PendingAuthorization> {
  const [row] = await ctx.db.query<Omit<PendingAuthorization, 'client_name' | 'redirect_host' | 'previously_granted'> & { metadata: ClientMetadata }>(
    `select a.*, c.metadata, c.created_at as client_first_seen
     from oauth_authorizations a join oauth_clients c on c.client_id = a.client_id where a.id = $1`,
    [id],
  );
  if (!row || row.expires_at <= ctx.clock.now()) throw notFound('This sign-in link expired. Start the connection again from your agent.');
  const [prior] = await ctx.db.query('select 1 from grants where client_id = $1 limit 1', [row.client_id]);
  const { metadata, ...rest } = row;
  return { ...rest, client_name: clientDisplayName(row.client_id, metadata), redirect_host: redirectHost(metadata), previously_granted: !!prior };
}

const commaList = z
  .union([z.string(), z.array(z.string())])
  .transform(v => (Array.isArray(v) ? v : v.split(',')).map(s => s.trim()).filter(Boolean));

export const consentSchema = z.object({
  workspaceId: z.uuid(),
  folder: folderSchema,
  tags: commaList.pipe(z.array(tagSchema).max(50)).default([]),
  names: commaList.pipe(z.array(pathSchema).max(50)).default([]),
  label: z.string().trim().max(80).optional(),
});

function withParams(uri: string, params: Record<string, string | null>): string {
  const url = new URL(uri);
  for (const [k, v] of Object.entries(params)) if (v !== null) url.searchParams.set(k, v);
  return url.href;
}

export async function approveAuthorization(ctx: AppContext, user: User, id: string, input: z.input<typeof consentSchema>, ip?: string): Promise<string> {
  const data = consentSchema.parse(input);
  const authz = await getAuthorization(ctx, id);
  if (!(await roleIn(ctx, user.id, data.workspaceId))) throw forbidden();
  const now = ctx.clock.now();
  const grantId = randomUUID();
  const code = randomToken('akac_');
  const scope = { folder: data.folder, tags: data.tags, names: data.names };
  const consumed = await ctx.db.tx(async q => {
    const deleted = await q.query('delete from oauth_authorizations where id = $1 returning id', [id]);
    if (deleted.length !== 1) return false;
    await q.query(
      `insert into grants (id, workspace_id, client_id, user_id, label, scope_folder, scope_tags, scope_names, created_at)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [grantId, data.workspaceId, authz.client_id, user.id, data.label || authz.client_name, data.folder, data.tags, data.names, now],
    );
    await q.query(
      `insert into oauth_codes (code_hash, grant_id, client_id, redirect_uri, code_challenge, resource, expires_at)
       values ($1,$2,$3,$4,$5,$6,$7)`,
      [hashToken(code), grantId, authz.client_id, authz.redirect_uri, authz.code_challenge, authz.resource, addSeconds(now, CODE_TTL)],
    );
    return true;
  });
  if (!consumed) throw new AppError('already_used', 'This sign-in request was already completed');
  await audit(ctx, {
    workspaceId: data.workspaceId,
    actor: { type: 'user', id: user.id, label: user.email },
    action: 'grant.create',
    outcome: 'success',
    grantId,
    ip,
    detail: { client: authz.client_name, client_id: authz.client_id, scope: describeScope(scope) },
  });
  return withParams(authz.redirect_uri, { code, state: authz.state });
}

export async function denyAuthorization(ctx: AppContext, id: string): Promise<string> {
  const authz = await getAuthorization(ctx, id);
  await ctx.db.query('delete from oauth_authorizations where id = $1', [id]);
  return withParams(authz.redirect_uri, { error: 'access_denied', error_description: 'The user denied access', state: authz.state });
}
