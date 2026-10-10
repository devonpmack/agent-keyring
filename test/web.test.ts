import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { startFakeGoogle, type FakeIdentity } from '../dev/fake-google.js';
import { addSecret, api, browserFor, codeFor, connectAgent, enrollAuthenticator, form, page, refreshUser, signInAs, startEnv, type TestEnv } from './helpers.js';

describe('Google sign-in', () => {
  let env: TestEnv;
  let oidc: Awaited<ReturnType<typeof startFakeGoogle>>;
  beforeEach(async () => {
    oidc = await startFakeGoogle('test');
    env = await startEnv({ google: { issuer: oidc.issuer, clientId: 'test', clientSecret: 'test' } });
  });
  afterEach(async () => {
    await env.close();
    await oidc.close();
  });

  // Follows the redirect chain like a browser, carrying cookies.
  async function signInFlow(identity: FakeIdentity, start = '/auth/google?return_to=/agents', jar = new Map<string, string>()) {
    oidc.state.next = identity;
    let url = env.baseUrl + start;
    let res: Response | undefined;
    for (let i = 0; i < 6; i++) {
      const cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
      res = await fetch(url, { redirect: 'manual', headers: { cookie, accept: 'text/html' } });
      for (const set of res.headers.getSetCookie()) {
        const [pair] = set.split(';');
        const [k, v] = pair!.split('=');
        if (set.includes('Expires=Thu, 01 Jan 1970')) jar.delete(k!);
        else jar.set(k!, v!);
      }
      const location = res.headers.get('location');
      if (!location || res.status < 300 || res.status >= 400) break;
      url = new URL(location, url).href;
      if (url.startsWith(env.baseUrl) && !url.includes('/auth/')) break;
    }
    return { res: res!, finalUrl: url, jar };
  }

  it('signs in the owner and redirects back', async () => {
    const { finalUrl, jar } = await signInFlow({ sub: 'g-1', email: 'Owner@Example.com', email_verified: true, name: 'Owner' });
    expect(finalUrl).toBe(`${env.baseUrl}/agents`);
    expect(jar.has('ak_session')).toBe(true);
    const [user] = await env.ctx.db.query<{ email: string }>('select email from users');
    expect(user?.email).toBe('owner@example.com');
  });

  it('refuses accounts not on the allowlist and unverified emails', async () => {
    const stranger = await signInFlow({ sub: 'g-2', email: 'stranger@example.com', email_verified: true, name: 'S' });
    expect(stranger.res.status).toBe(403);
    expect(await stranger.res.text()).toContain('not on this keyring');
    const unverified = await signInFlow({ sub: 'g-3', email: 'owner@example.com', email_verified: false, name: 'O' });
    expect(unverified.res.status).toBe(403);
  });

  const now = () => Math.floor(env.clock.now().getTime() / 1000);
  const owner = (authTime?: number): FakeIdentity => ({ sub: 'g-1', email: 'owner@example.com', email_verified: true, name: 'Owner', auth_time: authTime });

  it('re-auth asks Google for max_age and requires the same account', async () => {
    const { jar } = await signInFlow(owner());
    env.clock.advance(6 * 60);
    const fresh = await signInFlow(owner(now()), '/secrets/new', jar);
    expect(oidc.state.lastAuthorize?.get('max_age')).toBe('0');
    expect(fresh.finalUrl).toBe(`${env.baseUrl}/secrets/new`);
    env.clock.advance(6 * 60);
    const other = await signInFlow({ sub: 'g-9', email: 'other@example.com', email_verified: true, name: 'X', auth_time: now() }, '/auth/google?purpose=reauth&return_to=/', jar);
    expect(other.res.status).toBe(403);
  });

  it('re-auth is refused when Google does not prove a fresh sign-in', async () => {
    const { jar } = await signInFlow(owner());
    env.clock.advance(6 * 60);
    const missing = await signInFlow(owner(), '/auth/google?purpose=reauth&return_to=/', jar);
    expect(missing.res.status).toBe(403);
    const old = await signInFlow(owner(now() - 3600), '/auth/google?purpose=reauth&return_to=/', jar);
    expect(old.res.status).toBe(403);
  });

  it('rejects a callback without the browser-bound login state', async () => {
    oidc.state.next = { sub: 'g-1', email: 'owner@example.com', email_verified: true, name: 'O' };
    const res = await fetch(`${env.baseUrl}/auth/callback?code=x&state=y`, { headers: { accept: 'text/html' } });
    expect(res.status).toBe(400);
  });
});

describe('web UI protections', () => {
  let env: TestEnv;
  beforeEach(async () => {
    env = await startEnv();
  });
  afterEach(async () => env.close());

  it('requires sign-in', async () => {
    const res = await page(env, undefined, '/approvals');
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/login?return_to=%2Fapprovals');
  });

  it('rejects state changes without the CSRF token or from another origin', async () => {
    const o = await signInAs(env, 'owner@example.com');
    const b = await browserFor(env, o.user, o.workspaceId);
    const fields = { folder: 'x', name: 'Y', kind: 'static', value: 'v', policy: 'open' };
    expect((await form(env, { ...b, csrf: 'wrong' }, '/secrets', fields)).status).toBe(403);
    const cross = await fetch(`${env.baseUrl}/secrets`, {
      method: 'POST',
      redirect: 'manual',
      headers: { cookie: b.cookie, origin: 'https://evil.example', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ _csrf: b.csrf, ...fields }).toString(),
    });
    expect(cross.status).toBe(403);
    expect((await form(env, b, '/secrets', fields)).status).toBe(303);
  });

  it('requires a recent Google re-auth for admin actions', async () => {
    const o = await signInAs(env, 'owner@example.com');
    const b = await browserFor(env, o.user, o.workspaceId);
    env.clock.advance(6 * 60);
    const create = await form(env, b, '/secrets', { folder: '', name: 'X', kind: 'static', value: 'v', policy: 'open' });
    expect(create.status).toBe(401);
    expect(await create.text()).toContain('purpose=reauth&amp;return_to=%2Fsecrets%2Fnew');
    expect((await page(env, b, '/secrets/new')).headers.get('location')).toContain('/auth/google?purpose=reauth');
    expect((await form(env, b, '/settings/authenticator', {})).status).toBe(401);
    // Viewing and approving do not need re-auth.
    expect((await page(env, b, '/')).status).toBe(200);
  });

  it('ignores flash text in the URL, so an agent cannot add words to the approval page', async () => {
    const o = await signInAs(env, 'owner@example.com');
    const b = await browserFor(env, o.user, o.workspaceId);
    const html = await (await page(env, b, '/?flash=Verified%20safe%20to%20approve')).text();
    expect(html).not.toContain('Verified safe to approve');
  });

  it('replacing an enrolled authenticator needs a current code from it', async () => {
    const o = await signInAs(env, 'owner@example.com');
    const seed = await enrollAuthenticator(env, o.user);
    const b = await browserFor(env, await refreshUser(env, o.user), o.workspaceId);
    expect((await form(env, b, '/settings/authenticator', {})).status).toBe(400);
    expect((await form(env, b, '/settings/authenticator', { current_code: '000000' })).status).toBe(400);
    const ok = await form(env, b, '/settings/authenticator', { current_code: await codeFor(env, seed) });
    expect(ok.status).toBe(200);
    expect(await ok.text()).toContain('Scan this with Google Authenticator');
  });

  it('the consent page shows where the code is really sent', async () => {
    const o = await signInAs(env, 'owner@example.com');
    const b = await browserFor(env, o.user, o.workspaceId);
    const reg = await (await fetch(`${env.baseUrl}/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_name: 'Claude Code', redirect_uris: ['http://127.0.0.1:33418/callback', 'https://attacker.example/cb'] }),
    })).json();
    const auth = await fetch(`${env.baseUrl}/authorize?${new URLSearchParams({ response_type: 'code', client_id: reg.client_id, redirect_uri: 'https://attacker.example/cb', code_challenge: 'x'.repeat(43), code_challenge_method: 'S256' })}`, { redirect: 'manual' });
    const html = await (await page(env, b, auth.headers.get('location')!)).text();
    expect(html).toContain('https://attacker.example/cb');
    expect(html).toContain('This is a website, not an app on your computer');
    expect(html).not.toContain('<code>http://127.0.0.1:33418');
  });

  it('sets security headers and keeps secret values off every page', async () => {
    const o = await signInAs(env, 'owner@example.com');
    const b = await browserFor(env, o.user, o.workspaceId);
    const secret = await addSecret(env, o, { path: 'prod/KEY', value: 'sk_FAKE_value_123', policy: 'open' });
    for (const path of ['/', `/secrets/${secret.id}`, '/audit']) {
      const res = await page(env, b, path);
      expect(res.status).toBe(200);
      expect(await res.text()).not.toContain('sk_FAKE_value_123');
      expect(res.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
      expect(res.headers.get('cache-control')).toBe('no-store');
    }
  });

  it('owner manages the allowlist; removing a member revokes their agents', async () => {
    const o = await signInAs(env, 'owner@example.com');
    const ob = await browserFor(env, o.user, o.workspaceId);
    expect((await form(env, ob, '/members', { email: 'Teammate@Example.com' })).status).toBe(303);
    const t = await signInAs(env, 'teammate@example.com');
    expect(t.workspaceId).toBe(o.workspaceId);
    const tb = await browserFor(env, t.user, t.workspaceId);
    expect((await form(env, tb, '/members', { email: 'x@example.com' })).status).toBe(403);
    const agent = await connectAgent(env, tb, { folder: '' }, { resource: 'v1' });
    expect((await api(env, agent, 'GET', '/v1/secrets')).status).toBe(200);
    expect((await form(env, ob, '/members/remove', { email: 'teammate@example.com' })).status).toBe(303);
    expect((await api(env, agent, 'GET', '/v1/secrets')).status).toBe(401);
    // Their session stops working too.
    expect((await page(env, tb, '/')).status).toBe(302);
  });

  it('managed mode: an invite never pulls a new user into someone else\'s workspace', async () => {
    await env.close();
    env = await startEnv({ mode: 'managed', ownerEmail: undefined });
    const mallory = await signInAs(env, 'mallory@example.com');
    const mb = await browserFor(env, mallory.user, mallory.workspaceId);
    expect((await form(env, mb, '/members', { email: 'victim@example.com' })).status).toBe(303);
    const victim = await signInAs(env, 'victim@example.com');
    expect(victim.workspaceId).not.toBe(mallory.workspaceId);
    const [role] = await env.ctx.db.query<{ role: string }>('select role from memberships where workspace_id = $1 and user_id = $2', [victim.workspaceId, victim.user.id]);
    expect(role?.role).toBe('owner');
    const vb = await browserFor(env, victim.user, victim.workspaceId);
    const settings = await (await page(env, vb, '/settings')).text();
    expect(settings).toContain('Invitations');
    // Accepting is explicit.
    expect((await form(env, vb, `/invites/${mallory.workspaceId}/accept`, {})).status).toBe(303);
    const [joined] = await env.ctx.db.query<{ user_id: string }>('select user_id from memberships where workspace_id = $1 and email = $2', [mallory.workspaceId, 'victim@example.com']);
    expect(joined?.user_id).toBe(victim.user.id);
  });

  it('managed mode gives each new user a private workspace', async () => {
    await env.close();
    env = await startEnv({ mode: 'managed', ownerEmail: undefined });
    const a = await signInAs(env, 'a@example.com');
    const b = await signInAs(env, 'b@example.com');
    expect(a.workspaceId).not.toBe(b.workspaceId);
    await addSecret(env, a, { path: 'A', value: 'fake-a', policy: 'open' });
    const bb = await browserFor(env, b.user, b.workspaceId);
    const agent = await connectAgent(env, bb, { folder: '' }, { resource: 'v1' });
    expect((await api(env, agent, 'GET', '/v1/secrets')).body.secrets).toEqual([]);
    // b cannot consent on behalf of a's workspace.
    const ab = await browserFor(env, a.user, a.workspaceId);
    await expect(connectAgent(env, { ...bb, workspaceId: ab.workspaceId }, { folder: '' })).rejects.toThrow();
  });
});
