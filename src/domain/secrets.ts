import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { contexts, open, seal, type Sealed } from '../crypto/envelope.js';
import { audit } from './audit.js';
import type { AppContext } from './context.js';
import { AppError, notFound } from './errors.js';
import { folderSchema, joinPath, segmentSchema, tagSchema } from './paths.js';
import { parseTotpSeed, type TotpParams } from './totp.js';
import type { User } from './users.js';

export type Kind = 'static' | 'totp_seed';
export type Policy = 'open' | 'approval';

export type SecretMeta = {
  id: string;
  workspace_id: string;
  folder: string;
  name: string;
  kind: Kind;
  policy: Policy;
  allow_chat_approval: boolean;
  notes: string;
  tags: string[];
  version: number;
  created_at: Date;
  updated_at: Date;
};

const META_COLUMNS = 'id, workspace_id, folder, name, kind, policy, allow_chat_approval, notes, tags, version, created_at, updated_at';

const tagsSchema = z
  .union([z.string(), z.array(z.string())])
  .transform(v => (Array.isArray(v) ? v : v.split(',')).map(t => t.trim().toLowerCase()).filter(Boolean))
  .pipe(z.array(tagSchema).max(20))
  .transform(tags => [...new Set(tags)]);

const commonFields = {
  notes: z.string().max(2000).default(''),
  tags: tagsSchema.default([]),
  policy: z.enum(['open', 'approval']),
  allowChatApproval: z.boolean().default(false),
};

export const createSecretSchema = z.object({
  folder: folderSchema,
  name: segmentSchema,
  kind: z.enum(['static', 'totp_seed']),
  value: z.string().min(1).max(65536),
  ...commonFields,
});

export const updateSecretSchema = z.object({
  ...commonFields,
  value: z.string().max(65536).optional(),
});

function storedValue(kind: Kind, value: string): string {
  if (kind === 'totp_seed') return JSON.stringify(parseTotpSeed(value));
  return value;
}

function actorOf(user: User) {
  return { type: 'user' as const, id: user.id, label: user.email };
}

export async function createSecret(ctx: AppContext, user: User, workspaceId: string, input: z.input<typeof createSecretSchema>): Promise<SecretMeta> {
  const data = createSecretSchema.parse(input);
  const id = randomUUID();
  const now = ctx.clock.now();
  const sealed = await seal(ctx.kms, storedValue(data.kind, data.value), contexts.secret(workspaceId, id));
  const path = joinPath(data.folder, data.name);
  try {
    const [row] = await ctx.db.query<SecretMeta>(
      `insert into secrets (id, workspace_id, folder, name, kind, policy, allow_chat_approval, notes, tags, value_sealed, created_by, created_at, updated_at)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12) returning ${META_COLUMNS}`,
      [id, workspaceId, data.folder, data.name, data.kind, data.policy, data.allowChatApproval, data.notes, data.tags, JSON.stringify(sealed), user.id, now],
    );
    await audit(ctx, { workspaceId, actor: actorOf(user), action: 'secret.create', outcome: 'success', secretPath: path, detail: { kind: data.kind, policy: data.policy, allow_chat_approval: data.allowChatApproval } });
    return row!;
  } catch (err) {
    if (String((err as { code?: string }).code) === '23505') throw new AppError('exists', `A secret named ${path} already exists`, 409);
    throw err;
  }
}

export async function updateSecret(ctx: AppContext, user: User, workspaceId: string, secretId: string, input: z.input<typeof updateSecretSchema>): Promise<SecretMeta> {
  const data = updateSecretSchema.parse(input);
  const before = await getSecret(ctx, workspaceId, secretId);
  const now = ctx.clock.now();
  const rotate = !!data.value;
  const sealed = rotate ? await seal(ctx.kms, storedValue(before.kind, data.value!), contexts.secret(workspaceId, secretId)) : null;
  const [row] = await ctx.db.query<SecretMeta>(
    `update secrets set notes = $3, tags = $4, policy = $5, allow_chat_approval = $6, updated_at = $7,
       value_sealed = coalesce($8, value_sealed), version = version + (case when $8::jsonb is null then 0 else 1 end)
     where workspace_id = $1 and id = $2 returning ${META_COLUMNS}`,
    [workspaceId, secretId, data.notes, data.tags, data.policy, data.allowChatApproval, now, sealed ? JSON.stringify(sealed) : null],
  );
  const path = joinPath(before.folder, before.name);
  if (before.policy !== data.policy || before.allow_chat_approval !== data.allowChatApproval) {
    await audit(ctx, {
      workspaceId,
      actor: actorOf(user),
      action: 'secret.policy_change',
      outcome: 'success',
      secretPath: path,
      detail: { from: before.policy, to: data.policy, allow_chat_approval: data.allowChatApproval },
    });
  }
  await audit(ctx, { workspaceId, actor: actorOf(user), action: 'secret.update', outcome: 'success', secretPath: path, detail: { value_rotated: rotate } });
  // A pending or approved request was for the old policy and value; make the agent ask again.
  await ctx.db.query(`update approval_requests set status = 'denied', decided_at = $2, decision_method = 'secret_changed' where secret_id = $1 and status in ('pending', 'approved')`, [secretId, now]);
  return row!;
}

export async function deleteSecret(ctx: AppContext, user: User, workspaceId: string, secretId: string): Promise<void> {
  const before = await getSecret(ctx, workspaceId, secretId);
  await ctx.db.query('delete from secrets where workspace_id = $1 and id = $2', [workspaceId, secretId]);
  await audit(ctx, { workspaceId, actor: actorOf(user), action: 'secret.delete', outcome: 'success', secretPath: joinPath(before.folder, before.name) });
}

export async function getSecret(ctx: Pick<AppContext, 'db'>, workspaceId: string, secretId: string): Promise<SecretMeta> {
  const [row] = await ctx.db.query<SecretMeta>(`select ${META_COLUMNS} from secrets where workspace_id = $1 and id = $2`, [workspaceId, secretId]);
  if (!row) throw notFound('Secret not found');
  return row;
}

export async function findSecretByPath(ctx: Pick<AppContext, 'db'>, workspaceId: string, folder: string, name: string): Promise<SecretMeta | undefined> {
  const [row] = await ctx.db.query<SecretMeta>(`select ${META_COLUMNS} from secrets where workspace_id = $1 and folder = $2 and name = $3`, [workspaceId, folder, name]);
  return row;
}

export async function listSecrets(ctx: Pick<AppContext, 'db'>, workspaceId: string): Promise<SecretMeta[]> {
  return ctx.db.query<SecretMeta>(`select ${META_COLUMNS} from secrets where workspace_id = $1 order by folder, name`, [workspaceId]);
}

// Every folder that holds a secret, plus its ancestors, so a grant can target a parent.
export function foldersOf(secrets: Pick<SecretMeta, 'folder'>[]): string[] {
  const set = new Set<string>();
  for (const { folder } of secrets) {
    const parts = folder ? folder.split('/') : [];
    for (let i = 1; i <= parts.length; i++) set.add(parts.slice(0, i).join('/'));
  }
  return [...set].sort();
}

export type Released = { kind: 'static'; value: string } | { kind: 'totp_seed'; params: TotpParams };

export async function decryptSecret(ctx: AppContext, secret: SecretMeta): Promise<Released> {
  const [row] = await ctx.db.query<{ value_sealed: Sealed }>('select value_sealed from secrets where id = $1', [secret.id]);
  if (!row) throw notFound('Secret not found');
  const plaintext = await open(ctx.kms, row.value_sealed, contexts.secret(secret.workspace_id, secret.id));
  if (secret.kind === 'totp_seed') return { kind: 'totp_seed', params: JSON.parse(plaintext) as TotpParams };
  return { kind: 'static', value: plaintext };
}
