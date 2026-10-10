import { createGuardrails, generate, generateSecret, generateURI, verify } from 'otplib';
import { z } from 'zod';
import { contexts, open, seal, type Sealed } from '../crypto/envelope.js';
import { audit } from './audit.js';
import type { AppContext } from './context.js';
import { addSeconds } from './context.js';
import { AppError } from './errors.js';
import type { User } from './users.js';

// ---- Third-party TOTP seeds stored as secrets (kind = totp_seed) ----

export type TotpParams = { secret: string; digits: 6 | 7 | 8; period: number; algorithm: 'sha1' | 'sha256' | 'sha512' };

const base32 = z
  .string()
  .transform(s => s.replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase())
  .refine(s => /^[A-Z2-7]{16,102}$/.test(s), 'TOTP seed must be base32, 16 to 102 characters');

// Many services still issue 80-bit seeds; otplib's default floor is 128 bits.
// Our own authenticator enrollment generates 160-bit seeds.
const thirdPartySeedGuardrails = createGuardrails({ MIN_SECRET_BYTES: 10 });

// Accepts a bare base32 seed or an otpauth://totp/ URI from a QR code.
export function parseTotpSeed(input: string): TotpParams {
  const trimmed = input.trim();
  if (!trimmed.toLowerCase().startsWith('otpauth://')) {
    return { secret: base32.parse(trimmed), digits: 6, period: 30, algorithm: 'sha1' };
  }
  const url = new URL(trimmed);
  if (url.host !== 'totp') throw new AppError('invalid_seed', 'Only otpauth://totp/ URIs are supported');
  const digits = Number(url.searchParams.get('digits') ?? 6);
  const period = Number(url.searchParams.get('period') ?? 30);
  const algorithm = (url.searchParams.get('algorithm') ?? 'SHA1').toLowerCase();
  if (digits !== 6 && digits !== 7 && digits !== 8) throw new AppError('invalid_seed', 'Unsupported digits');
  if (!Number.isInteger(period) || period < 15 || period > 300) throw new AppError('invalid_seed', 'Unsupported period');
  if (algorithm !== 'sha1' && algorithm !== 'sha256' && algorithm !== 'sha512') throw new AppError('invalid_seed', 'Unsupported algorithm');
  return { secret: base32.parse(url.searchParams.get('secret') ?? ''), digits, period, algorithm };
}

export async function currentCode(params: TotpParams, now: Date): Promise<{ code: string; expiresInSeconds: number }> {
  const epoch = Math.floor(now.getTime() / 1000);
  const code = await generate({ secret: params.secret, digits: params.digits, period: params.period, algorithm: params.algorithm, epoch, guardrails: thirdPartySeedGuardrails });
  return { code, expiresInSeconds: params.period - (epoch % params.period) };
}

// ---- The human's own authenticator, used to approve requests ----

const LOCK_AFTER_FAILURES = 5;
const LOCK_SECONDS = 15 * 60;

export async function startEnrollment(ctx: AppContext, user: User): Promise<{ uri: string; secret: string }> {
  const secret = generateSecret();
  const sealed = await seal(ctx.kms, secret, contexts.userTotp(user.id));
  await ctx.db.query('update users set totp_pending_sealed = $1 where id = $2', [JSON.stringify(sealed), user.id]);
  const uri = generateURI({ issuer: 'agent-keyring', label: user.email, secret });
  return { uri, secret };
}

export async function confirmEnrollment(ctx: AppContext, user: User, code: string, workspaceId: string | null): Promise<void> {
  const [row] = await ctx.db.query<{ totp_pending_sealed: Sealed | null }>('select totp_pending_sealed from users where id = $1', [user.id]);
  if (!row?.totp_pending_sealed) throw new AppError('no_enrollment', 'Start enrollment first');
  const secret = await open(ctx.kms, row.totp_pending_sealed, contexts.userTotp(user.id));
  const step = acceptedStep(await verify({ secret, token: normalizeCode(code), epoch: epochOf(ctx), epochTolerance: 30 }));
  if (step === undefined) throw new AppError('invalid_code', 'That code did not match. Check the time on your phone and try again.');
  await ctx.db.query(
    `update users set totp_sealed = totp_pending_sealed, totp_pending_sealed = null, totp_enrolled_at = $1,
       totp_last_step = $2, totp_failed_count = 0, totp_locked_until = null where id = $3`,
    [ctx.clock.now(), step, user.id],
  );
  await audit(ctx, { workspaceId, actor: { type: 'user', id: user.id, label: user.email }, action: 'authenticator.enroll', outcome: 'success' });
}

// otplib's result type covers HOTP too; TOTP results carry the matched time step.
function acceptedStep(result: Awaited<ReturnType<typeof verify>>): number | undefined {
  return result.valid && 'timeStep' in result ? result.timeStep : undefined;
}

function epochOf(ctx: Pick<AppContext, 'clock'>): number {
  return Math.floor(ctx.clock.now().getTime() / 1000);
}

export function normalizeCode(code: string): string {
  return code.replace(/\s/g, '');
}

export type TotpCheck = { ok: true } | { ok: false; locked: boolean };

// Verifies a user's authenticator code. Codes are single-use: a code is only
// accepted for a time step later than the last accepted one (RFC 6238 §5.2),
// so a code typed once, even into an agent chat, cannot be replayed.
// Repeated failures lock approvals for the user and raise an alert.
export async function verifyUserCode(ctx: AppContext, userId: string, code: string, workspaceId: string | null): Promise<TotpCheck> {
  const now = ctx.clock.now();
  const [row] = await ctx.db.query<{
    email: string;
    totp_sealed: Sealed | null;
    totp_last_step: number | null;
    totp_locked_until: Date | null;
  }>('select email, totp_sealed, totp_last_step, totp_locked_until from users where id = $1', [userId]);
  if (!row?.totp_sealed) throw new AppError('no_authenticator', 'The approver has not enrolled an authenticator');
  if (row.totp_locked_until && row.totp_locked_until > now) return { ok: false, locked: true };

  const token = normalizeCode(code);
  let step: number | undefined;
  if (/^\d{6}$/.test(token)) {
    const secret = await open(ctx.kms, row.totp_sealed, contexts.userTotp(userId));
    step = acceptedStep(await verify({
      secret,
      token,
      epoch: epochOf(ctx),
      epochTolerance: 30,
      ...(row.totp_last_step !== null ? { afterTimeStep: row.totp_last_step } : {}),
    }));
  }

  if (step !== undefined) {
    // Conditional update closes the race where two requests submit the same code.
    const claimed = await ctx.db.query(
      `update users set totp_last_step = $1, totp_failed_count = 0
       where id = $2 and (totp_last_step is null or totp_last_step < $1) returning id`,
      [step, userId],
    );
    if (claimed.length === 1) return { ok: true };
  }

  return recordFailure(ctx, userId, row.email, workspaceId, now);
}

async function recordFailure(ctx: AppContext, userId: string, email: string, workspaceId: string | null, now: Date): Promise<TotpCheck> {
  const lockUntil = addSeconds(now, LOCK_SECONDS);
  const [updated] = await ctx.db.query<{ totp_failed_count: number }>(
    'update users set totp_failed_count = totp_failed_count + 1 where id = $1 returning totp_failed_count',
    [userId],
  );
  if (!updated || updated.totp_failed_count < LOCK_AFTER_FAILURES) return { ok: false, locked: false };
  await ctx.db.query('update users set totp_locked_until = $2, totp_failed_count = 0 where id = $1', [userId, lockUntil]);
  await audit(ctx, { workspaceId, actor: { type: 'system', label: 'agent-keyring' }, action: 'authenticator.lockout', outcome: 'denied', detail: { user: email, until: lockUntil.toISOString() } });
  await ctx.notifier.notify({ type: 'totp_lockout', workspaceId, userEmail: email, until: lockUntil });
  return { ok: false, locked: true };
}
