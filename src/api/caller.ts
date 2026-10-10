import type { Request } from 'express';
import { callerFromGrant } from '../domain/access.js';
import type { Caller } from '../domain/approvals.js';
import type { AppContext } from '../domain/context.js';
import { AppError } from '../domain/errors.js';
import { clientDisplayName, type ClientMetadata, type Grant } from '../domain/grants.js';

// Turns a verified bearer token (req.auth, set by requireBearerAuth) into the
// grant it was issued under. The token verifier already rejected revoked grants.
export async function callerFor(ctx: AppContext, req: Request): Promise<{ caller: Caller; grant: Grant }> {
  const grantId = req.auth?.extra?.grantId;
  if (typeof grantId !== 'string') throw new AppError('unauthenticated', 'Missing grant', 401);
  const [row] = await ctx.db.query<Grant & { metadata: ClientMetadata }>(
    `select g.*, c.metadata from grants g join oauth_clients c on c.client_id = g.client_id where g.id = $1 and g.revoked_at is null`,
    [grantId],
  );
  if (!row) throw new AppError('unauthenticated', 'Access was revoked', 401);
  const { metadata, ...grant } = row;
  return { caller: callerFromGrant(grant, clientDisplayName(grant.client_id, metadata), req.ip), grant };
}
