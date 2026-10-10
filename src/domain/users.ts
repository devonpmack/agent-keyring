import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { audit } from './audit.js';
import type { AppContext } from './context.js';
import { AppError, forbidden } from './errors.js';

export type User = { id: string; email: string; name: string; totp_enrolled_at: Date | null };
export type Role = 'owner' | 'admin';
export type Membership = { workspace_id: string; workspace_name: string; role: Role };

export type GoogleIdentity = { sub: string; email: string; emailVerified: boolean; name: string };

// Self-hosted: one workspace, created on first boot with OWNER_EMAIL as owner;
// everyone else must be on its allowlist. Managed: anyone may sign in and always
// gets a workspace of their own; invites to other workspaces wait for an
// explicit accept, so nobody can pull a new user into a workspace they control.
export async function ensureSelfHostedWorkspace(ctx: AppContext): Promise<void> {
  if (ctx.config.mode !== 'self_hosted' || !ctx.config.ownerEmail) return;
  const [existing] = await ctx.db.query('select id from workspaces limit 1');
  if (existing) return;
  const now = ctx.clock.now();
  const id = randomUUID();
  await ctx.db.tx(async q => {
    await q.query('insert into workspaces (id, name, created_at) values ($1, $2, $3)', [id, 'Keyring', now]);
    await q.query(
      `insert into memberships (workspace_id, email, role, created_at) values ($1, $2, 'owner', $3)`,
      [id, ctx.config.ownerEmail, now],
    );
  });
}

export async function signIn(ctx: AppContext, identity: GoogleIdentity, ip?: string): Promise<{ user: User; workspaceId: string }> {
  if (!identity.emailVerified) throw forbidden('Your Google email address is not verified');
  const email = identity.email.toLowerCase();
  const now = ctx.clock.now();

  return ctx.db.tx(async q => {
    const [user] = await q.query<User>(
      `insert into users (id, google_sub, email, name, created_at) values ($1, $2, $3, $4, $5)
       on conflict (google_sub) do update set email = excluded.email, name = excluded.name
       returning id, email, name, totp_enrolled_at`,
      [randomUUID(), identity.sub, email, identity.name, now],
    );
    if (!user) throw new Error('user upsert failed');

    if (ctx.config.mode === 'self_hosted') {
      // The owner allowlisted this email for the only workspace there is.
      await q.query('update memberships set user_id = $1 where email = $2 and user_id is null', [user.id, email]);
    } else {
      const [owned] = await q.query(`select 1 from memberships where user_id = $1 and role = 'owner' limit 1`, [user.id]);
      if (!owned) {
        const workspaceId = randomUUID();
        const label = identity.name ? `${identity.name}'s keyring` : 'My keyring';
        await q.query('insert into workspaces (id, name, created_at) values ($1, $2, $3)', [workspaceId, label, now]);
        await q.query(
          `insert into memberships (workspace_id, email, user_id, role, created_at) values ($1, $2, $3, 'owner', $4)`,
          [workspaceId, email, user.id, now],
        );
      }
    }
    // Owner rows sort first, so a managed user lands in their own workspace.
    const memberships = await q.query<{ workspace_id: string; role: Role }>(
      'select workspace_id, role from memberships where user_id = $1 order by role desc, created_at',
      [user.id],
    );

    const first = memberships[0];
    if (!first) {
      await audit(ctx, { workspaceId: null, actor: { type: 'user', id: user.id, label: email }, action: 'auth.login', outcome: 'denied', ip, detail: { why: 'not_allowlisted' } }, q);
      throw forbidden(`${email} is not on this keyring's allowlist`);
    }
    await audit(ctx, { workspaceId: first.workspace_id, actor: { type: 'user', id: user.id, label: email }, action: 'auth.login', outcome: 'success', ip }, q);
    return { user, workspaceId: first.workspace_id };
  });
}

export async function getUser(ctx: Pick<AppContext, 'db'>, userId: string): Promise<User | undefined> {
  const [user] = await ctx.db.query<User>('select id, email, name, totp_enrolled_at from users where id = $1', [userId]);
  return user;
}

export async function listMemberships(ctx: Pick<AppContext, 'db'>, userId: string): Promise<Membership[]> {
  return ctx.db.query<Membership>(
    `select m.workspace_id, w.name as workspace_name, m.role
     from memberships m join workspaces w on w.id = m.workspace_id
     where m.user_id = $1 order by w.created_at`,
    [userId],
  );
}

export async function roleIn(ctx: Pick<AppContext, 'db'>, userId: string, workspaceId: string): Promise<Role | undefined> {
  const [row] = await ctx.db.query<{ role: Role }>(
    'select role from memberships where user_id = $1 and workspace_id = $2',
    [userId, workspaceId],
  );
  return row?.role;
}

export type Member = { email: string; role: Role; user_id: string | null; created_at: Date };

export async function listMembers(ctx: Pick<AppContext, 'db'>, workspaceId: string): Promise<Member[]> {
  return ctx.db.query<Member>(
    'select email, role, user_id, created_at from memberships where workspace_id = $1 order by role desc, email',
    [workspaceId],
  );
}

const emailSchema = z.email().transform(e => e.toLowerCase());

export async function addMember(ctx: AppContext, actor: User, workspaceId: string, rawEmail: string): Promise<void> {
  const parsed = emailSchema.safeParse(rawEmail.trim());
  if (!parsed.success) throw new AppError('invalid_email', 'Enter a valid email address');
  const email = parsed.data;
  // Self-hosted members join immediately; managed invites stay pending until accepted.
  const [existingUser] = ctx.config.mode === 'self_hosted' ? await ctx.db.query<{ id: string }>('select id from users where email = $1', [email]) : [];
  await ctx.db.query(
    `insert into memberships (workspace_id, email, user_id, role, created_at) values ($1, $2, $3, 'admin', $4)
     on conflict (workspace_id, email) do nothing`,
    [workspaceId, email, existingUser?.id ?? null, ctx.clock.now()],
  );
  await audit(ctx, { workspaceId, actor: { type: 'user', id: actor.id, label: actor.email }, action: 'member.add', outcome: 'success', detail: { email } });
}

export async function removeMember(ctx: AppContext, actor: User, workspaceId: string, email: string): Promise<void> {
  await ctx.db.tx(async q => {
    const [removed] = await q.query<{ user_id: string | null }>(
      `delete from memberships where workspace_id = $1 and email = $2 and role <> 'owner' returning user_id`,
      [workspaceId, email.toLowerCase()],
    );
    if (!removed) throw new AppError('cannot_remove', 'That member cannot be removed');
    // Agents they connected lose access with them.
    if (removed.user_id) {
      await q.query(
        'update grants set revoked_at = $1, revoked_by = $2 where workspace_id = $3 and user_id = $4 and revoked_at is null',
        [ctx.clock.now(), actor.id, workspaceId, removed.user_id],
      );
    }
  });
  await audit(ctx, { workspaceId, actor: { type: 'user', id: actor.id, label: actor.email }, action: 'member.remove', outcome: 'success', detail: { email } });
}

export type Invite = { workspace_id: string; workspace_name: string; created_at: Date };

export async function listInvites(ctx: Pick<AppContext, 'db'>, user: User): Promise<Invite[]> {
  return ctx.db.query<Invite>(
    `select m.workspace_id, w.name as workspace_name, m.created_at
     from memberships m join workspaces w on w.id = m.workspace_id
     where m.email = $1 and m.user_id is null order by m.created_at`,
    [user.email],
  );
}

export async function acceptInvite(ctx: AppContext, user: User, workspaceId: string): Promise<void> {
  const rows = await ctx.db.query(
    'update memberships set user_id = $1 where workspace_id = $2 and email = $3 and user_id is null returning email',
    [user.id, workspaceId, user.email],
  );
  if (rows.length !== 1) throw new AppError('no_invite', 'That invite no longer exists');
  await audit(ctx, { workspaceId, actor: { type: 'user', id: user.id, label: user.email }, action: 'member.accept', outcome: 'success' });
}

export async function declineInvite(ctx: AppContext, user: User, workspaceId: string): Promise<void> {
  await ctx.db.query('delete from memberships where workspace_id = $1 and email = $2 and user_id is null', [workspaceId, user.email]);
}
