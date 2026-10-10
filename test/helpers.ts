import { createHash, randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { createServer } from 'node:http';
import { generate } from 'otplib';
import { createApp } from '../src/app.js';
import type { Config } from '../src/config.js';
import { LocalKms } from '../src/crypto/kms/local.js';
import { hashToken, randomToken } from '../src/crypto/tokens.js';
import { createPgliteDb } from '../src/db/index.js';
import { migrate } from '../src/db/migrate.js';
import type { AppContext, Clock } from '../src/domain/context.js';
import type { Notification, Notifier } from '../src/domain/notifier.js';
import { createSecret } from '../src/domain/secrets.js';
import { confirmEnrollment, startEnrollment } from '../src/domain/totp.js';
import { ensureSelfHostedWorkspace, getUser, signIn, type User } from '../src/domain/users.js';

export class FakeClock implements Clock {
  // Starts at real time: the SDK bearer middleware also checks expiry against Date.now().
  private t = Date.now();
  now(): Date {
    return new Date(this.t);
  }
  advance(seconds: number): void {
    this.t += seconds * 1000;
  }
}

export class MemoryNotifier implements Notifier {
  readonly sent: Notification[] = [];
  async notify(n: Notification): Promise<void> {
    this.sent.push(n);
  }
}

export type TestEnv = {
  ctx: AppContext;
  clock: FakeClock;
  notifier: MemoryNotifier;
  baseUrl: string;
  close(): Promise<void>;
};

// A real HTTP server on a random port, backed by in-process Postgres (PGlite)
// and the local KMS adapter. BASE_URL is only known after listen, so the app
// is attached once the port is bound.
export async function startEnv(overrides: Partial<Config> = {}): Promise<TestEnv> {
  const db = createPgliteDb();
  await migrate(db);
  const clock = new FakeClock();
  const notifier = new MemoryNotifier();
  const config = {
    nodeEnv: 'test',
    port: 0,
    baseUrl: 'http://localhost:0',
    mode: 'self_hosted',
    ownerEmail: 'owner@example.com',
    databaseUrl: 'pglite',
    trustProxy: 0,
    google: { issuer: 'http://localhost:1/unused', clientId: 'test', clientSecret: 'test' },
    kms: { provider: 'local', keyFile: 'unused' },
    allowLocalKmsInProduction: false,
    ...overrides,
  } as Config;
  const ctx: AppContext = { config, db, kms: new LocalKms(randomBytes(32)), clock, notifier };
  const server = createServer();
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  config.baseUrl = `http://localhost:${(server.address() as AddressInfo).port}`;
  server.on('request', createApp(ctx));
  await ensureSelfHostedWorkspace(ctx);
  return {
    ctx,
    clock,
    notifier,
    baseUrl: config.baseUrl,
    async close() {
      await new Promise(resolve => server.close(resolve));
      await db.close();
    },
  };
}

export async function signInAs(env: TestEnv, email: string): Promise<{ user: User; workspaceId: string }> {
  return signIn(env.ctx, { sub: 'google-' + email, email, emailVerified: true, name: email.split('@')[0]! });
}

export type Browser = { cookie: string; csrf: string; user: User; workspaceId: string };

// Creates a session row directly (Google sign-in itself is covered separately).
export async function browserFor(env: TestEnv, user: User, workspaceId: string): Promise<Browser> {
  const token = randomToken('');
  const csrf = randomToken('', 24);
  const now = env.clock.now();
  await env.ctx.db.query(
    `insert into sessions (id_hash, user_id, workspace_id, csrf_token, created_at, expires_at, auth_at) values ($1,$2,$3,$4,$5,$6,$5)`,
    [hashToken(token), user.id, workspaceId, csrf, now, new Date(now.getTime() + 12 * 3600_000)],
  );
  return { cookie: `ak_session=${token}`, csrf, user, workspaceId };
}

export async function form(env: TestEnv, browser: Browser, path: string, fields: Record<string, string>): Promise<Response> {
  return fetch(env.baseUrl + path, {
    method: 'POST',
    redirect: 'manual',
    headers: { cookie: browser.cookie, 'content-type': 'application/x-www-form-urlencoded', accept: 'text/html' },
    body: new URLSearchParams({ _csrf: browser.csrf, ...fields }).toString(),
  });
}

export async function page(env: TestEnv, browser: Browser | undefined, path: string): Promise<Response> {
  return fetch(env.baseUrl + path, { redirect: 'manual', headers: { ...(browser ? { cookie: browser.cookie } : {}), accept: 'text/html' } });
}

export async function enrollAuthenticator(env: TestEnv, user: User): Promise<string> {
  const { secret } = await startEnrollment(env.ctx, user);
  // Enroll one period in the past so the first approval code is a fresh step.
  env.clock.advance(-30);
  await confirmEnrollment(env.ctx, user, await codeFor(env, secret), null);
  env.clock.advance(30);
  return secret;
}

export async function codeFor(env: TestEnv, secret: string): Promise<string> {
  return generate({ secret, epoch: Math.floor(env.clock.now().getTime() / 1000) });
}

export type Agent = { accessToken: string; refreshToken: string; clientId: string; resource: string };

function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}

// The full OAuth 2.1 dance a client like Claude Code performs.
export async function connectAgent(
  env: TestEnv,
  browser: Browser,
  scope: { folder: string; tags?: string; names?: string },
  opts: { resource?: 'mcp' | 'v1'; clientName?: string } = {},
): Promise<Agent> {
  const resource = `${env.baseUrl}/${opts.resource ?? 'mcp'}`;
  const redirectUri = 'http://127.0.0.1:33418/callback';
  const reg = await fetch(`${env.baseUrl}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: opts.clientName ?? 'Test Agent', redirect_uris: [redirectUri], token_endpoint_auth_method: 'none' }),
  });
  if (reg.status !== 201) throw new Error(`register failed ${reg.status} ${await reg.text()}`);
  const client = (await reg.json()) as { client_id: string };
  const { verifier, challenge } = pkce();
  const authorize = new URL(`${env.baseUrl}/authorize`);
  authorize.search = new URLSearchParams({
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: redirectUri,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: 'xyz',
    resource,
  }).toString();
  const authRes = await fetch(authorize, { redirect: 'manual' });
  const consentPath = authRes.headers.get('location');
  if (!consentPath?.startsWith('/oauth/consent/')) throw new Error(`unexpected authorize redirect ${authRes.status} ${consentPath}`);
  const consent = await form(env, browser, consentPath, {
    decision: 'approve',
    workspaceId: browser.workspaceId,
    folder: scope.folder,
    tags: scope.tags ?? '',
    names: scope.names ?? '',
  });
  const callback = new URL(consent.headers.get('location') ?? '');
  const code = callback.searchParams.get('code');
  if (!code || callback.searchParams.get('state') !== 'xyz') throw new Error(`consent failed ${consent.status} ${callback}`);
  const tokens = await exchange(env, { grant_type: 'authorization_code', code, code_verifier: verifier, client_id: client.client_id, redirect_uri: redirectUri, resource });
  if (tokens.status !== 200) throw new Error(`token failed ${JSON.stringify(tokens.body)}`);
  return { accessToken: tokens.body.access_token!, refreshToken: tokens.body.refresh_token!, clientId: client.client_id, resource };
}

export async function exchange(env: TestEnv, params: Record<string, string>): Promise<{ status: number; body: Record<string, string> }> {
  const res = await fetch(`${env.baseUrl}/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(params).toString() });
  return { status: res.status, body: (await res.json()) as Record<string, string> };
}

export async function api(env: TestEnv, agent: Agent, method: string, path: string, body?: unknown): Promise<{ status: number; body: any }> {
  const res = await fetch(env.baseUrl + path, {
    method,
    headers: { authorization: `Bearer ${agent.accessToken}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => null) };
}

export async function addSecret(env: TestEnv, owner: { user: User; workspaceId: string }, s: { path: string; value: string; policy: 'open' | 'approval'; kind?: 'static' | 'totp_seed'; tags?: string[]; allowChatApproval?: boolean }) {
  const idx = s.path.lastIndexOf('/');
  return createSecret(env.ctx, owner.user, owner.workspaceId, {
    folder: idx === -1 ? '' : s.path.slice(0, idx),
    name: idx === -1 ? s.path : s.path.slice(idx + 1),
    kind: s.kind ?? 'static',
    value: s.value,
    policy: s.policy,
    tags: s.tags ?? [],
    allowChatApproval: s.allowChatApproval ?? false,
  });
}

export async function refreshUser(env: TestEnv, user: User): Promise<User> {
  return (await getUser(env.ctx, user.id))!;
}

// Agents refresh like a real client would after the 10-minute access token expires.
export async function refreshAgent(env: TestEnv, agent: Agent): Promise<void> {
  const res = await exchange(env, { grant_type: 'refresh_token', refresh_token: agent.refreshToken, client_id: agent.clientId });
  if (res.status !== 200) throw new Error(`refresh failed ${JSON.stringify(res.body)}`);
  agent.accessToken = res.body.access_token!;
  agent.refreshToken = res.body.refresh_token!;
}
