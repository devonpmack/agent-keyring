import { audit } from './audit.js';
import type { AppContext } from './context.js';
import { notFound } from './errors.js';
import type { GrantScope } from './paths.js';
import type { User } from './users.js';

export type Grant = {
  id: string;
  workspace_id: string;
  client_id: string;
  user_id: string;
  label: string;
  scope_folder: string;
  scope_tags: string[];
  scope_names: string[];
  created_at: Date;
  last_used_at: Date | null;
  revoked_at: Date | null;
};

export type GrantListing = Grant & { client_name: string; redirect_host: string; user_email: string };

export function scopeOf(grant: Pick<Grant, 'scope_folder' | 'scope_tags' | 'scope_names'>): GrantScope {
  return { folder: grant.scope_folder, tags: grant.scope_tags, names: grant.scope_names };
}

export type ClientMetadata = { client_name?: string; redirect_uris: string[]; client_uri?: string };

export function clientDisplayName(clientId: string, metadata: ClientMetadata): string {
  return metadata.client_name?.slice(0, 80) || `Unnamed client ${clientId.slice(0, 8)}`;
}

export function redirectHost(metadata: ClientMetadata): string {
  const first = metadata.redirect_uris[0];
  if (!first) return '';
  try {
    const url = new URL(first);
    return url.host ? `${url.protocol}//${url.host}` : url.protocol;
  } catch {
    return '';
  }
}

export async function listGrants(ctx: Pick<AppContext, 'db'>, workspaceId: string): Promise<GrantListing[]> {
  const rows = await ctx.db.query<Grant & { metadata: ClientMetadata; user_email: string }>(
    `select g.*, c.metadata, u.email as user_email
     from grants g join oauth_clients c on c.client_id = g.client_id join users u on u.id = g.user_id
     where g.workspace_id = $1 order by g.revoked_at is not null, g.created_at desc`,
    [workspaceId],
  );
  return rows.map(({ metadata, ...g }) => ({ ...g, client_name: clientDisplayName(g.client_id, metadata), redirect_host: redirectHost(metadata) }));
}

export async function revokeGrant(ctx: AppContext, user: User, workspaceId: string, grantId: string): Promise<void> {
  const [row] = await ctx.db.query<{ id: string }>(
    'update grants set revoked_at = $3, revoked_by = $4 where workspace_id = $1 and id = $2 and revoked_at is null returning id',
    [workspaceId, grantId, ctx.clock.now(), user.id],
  );
  if (!row) throw notFound('Grant not found or already revoked');
  await audit(ctx, { workspaceId, actor: { type: 'user', id: user.id, label: user.email }, action: 'grant.revoke', outcome: 'success', grantId });
}
