import { createHash, randomBytes } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { addSecret, api, browserFor, connectAgent, exchange, form, signInAs, startEnv, type TestEnv } from './helpers.js';

describe('OAuth 2.1 for agents', () => {
  let env: TestEnv;
  beforeEach(async () => {
    env = await startEnv();
  });
  afterEach(async () => env.close());

  async function owner() {
    const o = await signInAs(env, 'owner@example.com');
    return { ...o, browser: await browserFor(env, o.user, o.workspaceId) };
  }

  it('advertises authorization server and protected resource metadata', async () => {
    const as = await (await fetch(`${env.baseUrl}/.well-known/oauth-authorization-server`)).json();
    expect(as.registration_endpoint).toBe(`${env.baseUrl}/register`);
    expect(as.code_challenge_methods_supported).toEqual(['S256']);
    const prm = await (await fetch(`${env.baseUrl}/.well-known/oauth-protected-resource/mcp`)).json();
    expect(prm.resource).toBe(`${env.baseUrl}/mcp`);
    const unauth = await fetch(`${env.baseUrl}/mcp`, { method: 'POST' });
    expect(unauth.status).toBe(401);
    expect(unauth.headers.get('www-authenticate')).toContain('resource_metadata=');
  });

  it('registers clients as public PKCE clients only', async () => {
    const res = await fetch(`${env.baseUrl}/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_name: 'x', redirect_uris: ['http://localhost:1234/cb'], token_endpoint_auth_method: 'client_secret_post' }),
    });
    const body = await res.json();
    expect(body.token_endpoint_auth_method).toBe('none');
    expect(body.client_secret).toBeUndefined();
    const bad = await fetch(`${env.baseUrl}/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ redirect_uris: ['http://evil.example.com/cb'] }),
    });
    expect(bad.status).toBe(400);
  });

  it('issues tokens through consent and lets the REST API list in-scope secrets', async () => {
    const o = await owner();
    await addSecret(env, o, { path: 'prod/A', value: 'fake-a', policy: 'open' });
    await addSecret(env, o, { path: 'dev/B', value: 'fake-b', policy: 'open' });
    const agent = await connectAgent(env, o.browser, { folder: 'prod' }, { resource: 'v1' });
    const list = await api(env, agent, 'GET', '/v1/secrets');
    expect(list.status).toBe(200);
    expect(list.body.secrets.map((s: { name: string }) => s.name)).toEqual(['prod/A']);
    expect(JSON.stringify(list.body)).not.toContain('fake-a');
  });

  it('rejects a wrong PKCE verifier and a replayed code', async () => {
    const o = await owner();
    const redirectUri = 'http://127.0.0.1:9/cb';
    const client = await (await fetch(`${env.baseUrl}/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ client_name: 'c', redirect_uris: [redirectUri], token_endpoint_auth_method: 'none' }) })).json();
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const auth = await fetch(`${env.baseUrl}/authorize?${new URLSearchParams({ response_type: 'code', client_id: client.client_id, redirect_uri: redirectUri, code_challenge: challenge, code_challenge_method: 'S256' })}`, { redirect: 'manual' });
    const consent = await form(env, o.browser, auth.headers.get('location')!, { decision: 'approve', workspaceId: o.workspaceId, folder: '' });
    const code = new URL(consent.headers.get('location')!).searchParams.get('code')!;
    const base = { grant_type: 'authorization_code', code, client_id: client.client_id, redirect_uri: redirectUri };
    expect((await exchange(env, { ...base, code_verifier: randomBytes(32).toString('base64url') })).status).toBe(400);
    expect((await exchange(env, { ...base, code_verifier: verifier })).status).toBe(200);
    const replay = await exchange(env, { ...base, code_verifier: verifier });
    expect(replay.status).toBe(400);
  });

  it('rotates refresh tokens and revokes the grant when an old one is replayed', async () => {
    const o = await owner();
    const agent = await connectAgent(env, o.browser, { folder: '' });
    const first = await exchange(env, { grant_type: 'refresh_token', refresh_token: agent.refreshToken, client_id: agent.clientId });
    expect(first.status).toBe(200);
    expect(first.body.refresh_token).not.toBe(agent.refreshToken);
    const replay = await exchange(env, { grant_type: 'refresh_token', refresh_token: agent.refreshToken, client_id: agent.clientId });
    expect(replay.status).toBe(400);
    // The rotated token died with the grant.
    const after = await exchange(env, { grant_type: 'refresh_token', refresh_token: first.body.refresh_token!, client_id: agent.clientId });
    expect(after.status).toBe(400);
    expect(env.notifier.sent.some(n => n.type === 'token_reuse')).toBe(true);
  });

  it('expires access tokens and binds them to their resource', async () => {
    const o = await owner();
    const agent = await connectAgent(env, o.browser, { folder: '' }, { resource: 'mcp' });
    // An MCP token is not valid at the REST API.
    expect((await api(env, agent, 'GET', '/v1/secrets')).status).toBe(401);
    const rest = await connectAgent(env, o.browser, { folder: '' }, { resource: 'v1' });
    expect((await api(env, rest, 'GET', '/v1/secrets')).status).toBe(200);
    env.clock.advance(11 * 60);
    expect((await api(env, rest, 'GET', '/v1/secrets')).status).toBe(401);
  });

  it('stops working immediately when a human revokes the grant', async () => {
    const o = await owner();
    const agent = await connectAgent(env, o.browser, { folder: '' }, { resource: 'v1' });
    const [grant] = await env.ctx.db.query<{ id: string }>('select id from grants');
    const res = await form(env, o.browser, `/agents/${grant!.id}/revoke`, {});
    expect(res.status).toBe(303);
    expect((await api(env, agent, 'GET', '/v1/secrets')).status).toBe(401);
    expect((await exchange(env, { grant_type: 'refresh_token', refresh_token: agent.refreshToken, client_id: agent.clientId })).status).toBe(400);
  });

  it('client revocation of the refresh token ends the grant', async () => {
    const o = await owner();
    const agent = await connectAgent(env, o.browser, { folder: '' }, { resource: 'v1' });
    const res = await fetch(`${env.baseUrl}/revoke`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ token: agent.refreshToken, client_id: agent.clientId }).toString() });
    expect(res.status).toBe(200);
    expect((await api(env, agent, 'GET', '/v1/secrets')).status).toBe(401);
  });

  it('denied consent redirects with access_denied and creates no grant', async () => {
    const o = await owner();
    const redirectUri = 'http://127.0.0.1:9/cb';
    const client = await (await fetch(`${env.baseUrl}/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ redirect_uris: [redirectUri], token_endpoint_auth_method: 'none' }) })).json();
    const auth = await fetch(`${env.baseUrl}/authorize?${new URLSearchParams({ response_type: 'code', client_id: client.client_id, code_challenge: 'x'.repeat(43), code_challenge_method: 'S256', state: 's' })}`, { redirect: 'manual' });
    const res = await form(env, o.browser, auth.headers.get('location')!, { decision: 'deny' });
    const loc = new URL(res.headers.get('location')!);
    expect(loc.searchParams.get('error')).toBe('access_denied');
    expect(loc.searchParams.get('state')).toBe('s');
    expect(await env.ctx.db.query('select 1 from grants')).toHaveLength(0);
  });
});
