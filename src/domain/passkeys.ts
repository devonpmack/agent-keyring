import { createHash, randomBytes } from 'node:crypto';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type WebAuthnCredential,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { audit } from './audit.js';
import type { AppContext } from './context.js';
import { AppError } from './errors.js';
import type { User } from './users.js';

// Passkey approval is the phishing-resistant alternative to typing a TOTP code:
// the authenticator signs a challenge derived from the approval request ID, and
// the browser only releases a signature to the vault's own origin.

export type Passkey = { id: string; user_id: string; public_key: string; counter: number; transports: string[]; name: string; created_at: Date; last_used_at: Date | null };
export type Challenge = { challenge: string; purpose: string };

function rp(ctx: Pick<AppContext, 'config'>) {
  const url = new URL(ctx.config.baseUrl);
  return { id: url.hostname, origin: url.origin };
}

export async function listPasskeys(ctx: Pick<AppContext, 'db'>, userId: string): Promise<Passkey[]> {
  return ctx.db.query<Passkey>('select * from passkeys where user_id = $1 order by created_at', [userId]);
}

export async function registrationOptions(ctx: AppContext, user: User): Promise<{ options: PublicKeyCredentialCreationOptionsJSON; challenge: Challenge }> {
  const existing = await listPasskeys(ctx, user.id);
  const options = await generateRegistrationOptions({
    rpName: 'agent-keyring',
    rpID: rp(ctx).id,
    userName: user.email,
    userDisplayName: user.name || user.email,
    userID: new TextEncoder().encode(user.id),
    attestationType: 'none',
    excludeCredentials: existing.map(p => ({ id: p.id, transports: p.transports })),
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
  });
  return { options, challenge: { challenge: options.challenge, purpose: 'register' } };
}

export async function finishRegistration(ctx: AppContext, user: User, workspaceId: string, expected: Challenge | null, response: RegistrationResponseJSON, name: string): Promise<void> {
  if (expected?.purpose !== 'register') throw new AppError('no_challenge', 'Start passkey registration again');
  const { origin, id } = rp(ctx);
  const result = await verifyRegistrationResponse({ response, expectedChallenge: expected.challenge, expectedOrigin: origin, expectedRPID: id, requireUserVerification: true });
  if (!result.verified) throw new AppError('passkey_failed', 'Passkey registration failed');
  const { credential } = result.registrationInfo;
  await ctx.db.query(
    'insert into passkeys (id, user_id, public_key, counter, transports, name, created_at) values ($1,$2,$3,$4,$5,$6,$7)',
    [credential.id, user.id, Buffer.from(credential.publicKey).toString('base64url'), credential.counter, credential.transports ?? [], name.slice(0, 60) || 'Passkey', ctx.clock.now()],
  );
  await audit(ctx, { workspaceId, actor: { type: 'user', id: user.id, label: user.email }, action: 'passkey.register', outcome: 'success' });
}

export async function deletePasskey(ctx: AppContext, user: User, workspaceId: string, id: string): Promise<void> {
  await ctx.db.query('delete from passkeys where id = $1 and user_id = $2', [id, user.id]);
  await audit(ctx, { workspaceId, actor: { type: 'user', id: user.id, label: user.email }, action: 'passkey.delete', outcome: 'success' });
}

export async function approvalOptions(ctx: AppContext, user: User, approvalId: string): Promise<{ options: PublicKeyCredentialRequestOptionsJSON; challenge: Challenge }> {
  const passkeys = await listPasskeys(ctx, user.id);
  if (passkeys.length === 0) throw new AppError('no_passkey', 'Register a passkey in Settings first');
  const challenge = createHash('sha256').update(`approve:${approvalId}:`).update(randomBytes(32)).digest('base64url');
  const options = await generateAuthenticationOptions({
    rpID: rp(ctx).id,
    challenge,
    userVerification: 'required',
    allowCredentials: passkeys.map(p => ({ id: p.id, transports: p.transports })),
  });
  return { options, challenge: { challenge: options.challenge, purpose: `approve:${approvalId}` } };
}

export async function verifyApprovalAssertion(ctx: AppContext, user: User, approvalId: string, expected: Challenge | null, response: AuthenticationResponseJSON): Promise<void> {
  if (expected?.purpose !== `approve:${approvalId}`) throw new AppError('no_challenge', 'Start passkey approval again');
  const [passkey] = await ctx.db.query<Passkey>('select * from passkeys where id = $1 and user_id = $2', [response.id, user.id]);
  if (!passkey) throw new AppError('unknown_passkey', 'That passkey is not registered to you');
  const { origin, id } = rp(ctx);
  const result = await verifyAuthenticationResponse({
    response,
    expectedChallenge: expected.challenge,
    expectedOrigin: origin,
    expectedRPID: id,
    requireUserVerification: true,
    credential: {
      id: passkey.id,
      publicKey: new Uint8Array(Buffer.from(passkey.public_key, 'base64url')),
      counter: passkey.counter,
      transports: passkey.transports as WebAuthnCredential['transports'],
    },
  });
  if (!result.verified) throw new AppError('passkey_failed', 'Passkey check failed');
  await ctx.db.query('update passkeys set counter = $2, last_used_at = $3 where id = $1', [passkey.id, result.authenticationInfo.newCounter, ctx.clock.now()]);
}
