import { generate } from 'otplib';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  addSecret,
  api,
  browserFor,
  codeFor,
  connectAgent,
  enrollAuthenticator,
  form,
  page,
  refreshAgent,
  refreshUser,
  signInAs,
  startEnv,
  type Agent,
  type Browser,
  type TestEnv,
} from './helpers.js';

const STRIPE = 'sk_test_FAKE_never_real_123';

describe('approval policy', () => {
  let env: TestEnv;
  let owner: Browser;
  let seed: string;
  let agent: Agent;

  beforeEach(async () => {
    env = await startEnv();
    const o = await signInAs(env, 'owner@example.com');
    seed = await enrollAuthenticator(env, o.user);
    owner = await browserFor(env, await refreshUser(env, o.user), o.workspaceId);
    await addSecret(env, o, { path: 'prod/stripe/API_KEY', value: STRIPE, policy: 'approval', tags: ['billing'] });
    await addSecret(env, o, { path: 'prod/github/TOKEN', value: 'ghp_FAKE_open', policy: 'open', tags: ['ci'] });
    agent = await connectAgent(env, owner, { folder: 'prod' }, { resource: 'v1' });
  });
  afterEach(async () => env.close());

  const fetchSecret = (path: string, body: Record<string, unknown> = {}, who = agent) =>
    api(env, who, 'POST', `/v1/secrets/${path}/fetch`, { reason: 'deploying the billing service', ...body });

  async function approveOnWeb(requestId: string, code?: string) {
    return form(env, owner, `/approvals/${requestId}/approve`, { code: code ?? (await codeFor(env, seed)) });
  }

  it('returns open secrets on demand', async () => {
    const res = await fetchSecret('prod/github/TOKEN');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: 'ok', kind: 'static', value: 'ghp_FAKE_open' });
  });

  it('never returns an approval secret without a valid approval', async () => {
    const first = await fetchSecret('prod/stripe/API_KEY');
    expect(first.status).toBe(202);
    expect(first.body).toMatchObject({ status: 'pending_approval', name: 'prod/stripe/API_KEY', client: 'Test Agent', reason: 'deploying the billing service' });
    expect(first.body.approval_url).toBe(`${env.baseUrl}/approvals/${first.body.request_id}`);
    expect(JSON.stringify(first.body)).not.toContain(STRIPE);

    // Retrying while pending, or inventing request IDs, never yields the value.
    const again = await fetchSecret('prod/stripe/API_KEY', { request_id: first.body.request_id });
    expect(again.body.status).toBe('pending_approval');
    expect((await fetchSecret('prod/stripe/API_KEY', { request_id: 'AAAAAAAAAA' })).status).toBe(400);
    expect(JSON.stringify(again.body)).not.toContain(STRIPE);
  });

  it('shows the human exactly what is requested', async () => {
    const { body } = await fetchSecret('prod/stripe/API_KEY', { reason: 'rotate <script>alert(1)</script> keys' });
    const html = await (await page(env, owner, `/approvals/${body.request_id}`)).text();
    expect(html).toContain(body.request_id);
    expect(html).toContain('prod/stripe/API_KEY');
    expect(html).toContain('Test Agent');
    expect(html).toContain('rotate &lt;script&gt;alert(1)&lt;/script&gt; keys');
    expect(html).not.toContain('<script>alert(1)');
  });

  it('releases the value exactly once after web approval', async () => {
    const { body } = await fetchSecret('prod/stripe/API_KEY');
    const approve = await approveOnWeb(body.request_id);
    expect(approve.status).toBe(303);
    const got = await fetchSecret('prod/stripe/API_KEY', { request_id: body.request_id });
    expect(got.body).toMatchObject({ status: 'ok', value: STRIPE });
    const reuse = await fetchSecret('prod/stripe/API_KEY', { request_id: body.request_id });
    expect(reuse.status).toBe(409);
    expect(JSON.stringify(reuse.body)).not.toContain(STRIPE);
  });

  it('an approval is bound to its request, secret and agent', async () => {
    await addSecret(env, { user: owner.user, workspaceId: owner.workspaceId }, { path: 'prod/stripe/OTHER', value: 'other-fake', policy: 'approval' });
    const { body } = await fetchSecret('prod/stripe/API_KEY');
    await approveOnWeb(body.request_id);
    // Same request ID for a different secret: refused.
    expect((await fetchSecret('prod/stripe/OTHER', { request_id: body.request_id })).status).toBe(400);
    // Same request ID from a different agent with the same scope: refused.
    const other = await connectAgent(env, owner, { folder: 'prod' }, { resource: 'v1', clientName: 'Other Agent' });
    expect((await fetchSecret('prod/stripe/API_KEY', { request_id: body.request_id }, other)).status).toBe(400);
    // The rightful agent can still use it.
    expect((await fetchSecret('prod/stripe/API_KEY', { request_id: body.request_id })).body.value).toBe(STRIPE);
  });

  it('an expired request cannot be approved, and an expired approval cannot be used', async () => {
    const stale = await fetchSecret('prod/stripe/API_KEY');
    env.clock.advance(5 * 60 + 1);
    expect((await approveOnWeb(stale.body.request_id)).status).toBe(410);

    const { body } = await fetchSecret('prod/stripe/API_KEY');
    expect((await approveOnWeb(body.request_id)).status).toBe(303);
    env.clock.advance(5 * 60 + 1);
    await refreshAgent(env, agent);
    const late = await fetchSecret('prod/stripe/API_KEY', { request_id: body.request_id });
    expect(late.status).toBe(410);
    expect(JSON.stringify(late.body)).not.toContain(STRIPE);
  });

  it('a denied request stays denied', async () => {
    const { body } = await fetchSecret('prod/stripe/API_KEY');
    expect((await form(env, owner, `/approvals/${body.request_id}/deny`, {})).status).toBe(303);
    expect((await fetchSecret('prod/stripe/API_KEY', { request_id: body.request_id })).status).toBe(403);
    expect((await approveOnWeb(body.request_id)).status).toBe(409);
  });

  it('rejects a replayed authenticator code', async () => {
    const a = await fetchSecret('prod/stripe/API_KEY');
    const b = await fetchSecret('prod/stripe/API_KEY');
    const code = await codeFor(env, seed);
    expect((await approveOnWeb(a.body.request_id, code)).status).toBe(303);
    expect((await approveOnWeb(b.body.request_id, code)).status).toBe(400);
    expect((await fetchSecret('prod/stripe/API_KEY', { request_id: b.body.request_id })).body.status).toBe('pending_approval');
    // The next time step's code works.
    env.clock.advance(30);
    expect((await approveOnWeb(b.body.request_id)).status).toBe(303);
  });

  it('rejects a code from an earlier time step even if never used', async () => {
    const { body } = await fetchSecret('prod/stripe/API_KEY');
    const old = await generate({ secret: seed, epoch: Math.floor(env.clock.now().getTime() / 1000) - 120 });
    expect((await approveOnWeb(body.request_id, old)).status).toBe(400);
  });

  it('locks approvals and alerts after repeated wrong codes', async () => {
    const { body } = await fetchSecret('prod/stripe/API_KEY');
    for (let i = 0; i < 4; i++) expect((await approveOnWeb(body.request_id, '000000')).status).toBe(400);
    const second = await fetchSecret('prod/stripe/API_KEY');
    // Fifth failure across requests locks the approver.
    expect((await approveOnWeb(second.body.request_id, '000000')).status).toBe(423);
    // Even the right code is refused while locked.
    expect((await approveOnWeb(second.body.request_id)).status).toBe(423);
    expect(env.notifier.sent.find(n => n.type === 'totp_lockout')).toBeTruthy();
    const [event] = await env.ctx.db.query<{ action: string }>(`select action from audit_events where action = 'authenticator.lockout'`);
    expect(event).toBeTruthy();
    // A single request is denied after five wrong codes.
    const [req] = await env.ctx.db.query<{ status: string }>('select status from approval_requests where id = $1', [body.request_id]);
    expect(req?.status).toBe('pending');
    env.clock.advance(15 * 60 + 30);
    await refreshAgent(env, agent);
    const fresh = await fetchSecret('prod/stripe/API_KEY');
    expect((await approveOnWeb(fresh.body.request_id)).status).toBe(303);
  });

  it('denies a request outright after five wrong codes on it', async () => {
    const { body } = await fetchSecret('prod/stripe/API_KEY');
    for (let i = 0; i < 4; i++) await approveOnWeb(body.request_id, '000000');
    // Reset the approver's counter so the per-request limit is what trips.
    await env.ctx.db.query('update users set totp_failed_count = 0');
    await approveOnWeb(body.request_id, '000000');
    const [req] = await env.ctx.db.query<{ status: string }>('select status from approval_requests where id = $1', [body.request_id]);
    expect(req?.status).toBe('denied');
  });

  it('chat codes (path b) are refused unless the secret opts in', async () => {
    const { body } = await fetchSecret('prod/stripe/API_KEY');
    const res = await fetchSecret('prod/stripe/API_KEY', { request_id: body.request_id, totp_code: await codeFor(env, seed) });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('chat_approval_disabled');
  });

  it('chat codes work when opted in, and only with a request ID', async () => {
    await addSecret(env, { user: owner.user, workspaceId: owner.workspaceId }, { path: 'prod/npm/TOKEN', value: 'npm_FAKE', policy: 'approval', allowChatApproval: true });
    const code = await codeFor(env, seed);
    expect((await fetchSecret('prod/npm/TOKEN', { totp_code: code })).status).toBe(400);
    const a = await fetchSecret('prod/npm/TOKEN');
    expect(a.body.instructions).toContain('totp_code');
    const ok = await fetchSecret('prod/npm/TOKEN', { request_id: a.body.request_id, totp_code: code });
    expect(ok.body).toMatchObject({ status: 'ok', value: 'npm_FAKE' });
    // The same code cannot approve a second request.
    const b = await fetchSecret('prod/npm/TOKEN');
    expect((await fetchSecret('prod/npm/TOKEN', { request_id: b.body.request_id, totp_code: code })).status).toBe(400);
  });

  it('changing a policy voids outstanding approvals', async () => {
    const { body } = await fetchSecret('prod/stripe/API_KEY');
    await approveOnWeb(body.request_id);
    const [secret] = await env.ctx.db.query<{ id: string }>(`select id from secrets where name = 'API_KEY'`);
    await form(env, owner, `/secrets/${secret!.id}`, { notes: '', tags: 'billing', policy: 'approval', allowChatApproval: '1' });
    expect((await fetchSecret('prod/stripe/API_KEY', { request_id: body.request_id })).status).toBe(403);
  });
});

describe('grant scope enforcement', () => {
  let env: TestEnv;
  let owner: Browser;
  beforeEach(async () => {
    env = await startEnv();
    const o = await signInAs(env, 'owner@example.com');
    owner = await browserFor(env, o.user, o.workspaceId);
    await addSecret(env, o, { path: 'prod/A_KEY', value: 'fake-a', policy: 'open', tags: ['team-a'] });
    await addSecret(env, o, { path: 'prod/B_KEY', value: 'fake-b', policy: 'open', tags: ['team-b'] });
    await addSecret(env, o, { path: 'staging/C_KEY', value: 'fake-c', policy: 'open', tags: ['team-a'] });
  });
  afterEach(async () => env.close());

  it('a token scoped to tag A cannot fetch tag B', async () => {
    const agent = await connectAgent(env, owner, { folder: '', tags: 'team-a' }, { resource: 'v1' });
    expect((await api(env, agent, 'POST', '/v1/secrets/prod/A_KEY/fetch', { reason: 'testing scope' })).body.value).toBe('fake-a');
    const denied = await api(env, agent, 'POST', '/v1/secrets/prod/B_KEY/fetch', { reason: 'testing scope' });
    expect(denied.status).toBe(404);
    expect(JSON.stringify(denied.body)).not.toContain('fake-b');
    const list = await api(env, agent, 'GET', '/v1/secrets');
    expect(list.body.secrets.map((s: { name: string }) => s.name)).toEqual(['prod/A_KEY', 'staging/C_KEY']);
  });

  it('a token scoped to one folder cannot see or fetch other folders', async () => {
    const agent = await connectAgent(env, owner, { folder: 'staging' }, { resource: 'v1' });
    expect((await api(env, agent, 'POST', '/v1/secrets/prod/A_KEY/fetch', { reason: 'testing scope' })).status).toBe(404);
    expect((await api(env, agent, 'GET', '/v1/secrets')).body.secrets.map((s: { name: string }) => s.name)).toEqual(['staging/C_KEY']);
  });

  it('out-of-scope and missing secrets look the same', async () => {
    const agent = await connectAgent(env, owner, { folder: 'staging' }, { resource: 'v1' });
    const outOfScope = await api(env, agent, 'POST', '/v1/secrets/prod/A_KEY/fetch', { reason: 'testing scope' });
    const missing = await api(env, agent, 'POST', '/v1/secrets/prod/NOPE/fetch', { reason: 'testing scope' });
    expect(outOfScope.status).toBe(missing.status);
    expect(outOfScope.body.error).toBe(missing.body.error);
  });

  it('requires a reason and validates input', async () => {
    const agent = await connectAgent(env, owner, { folder: '' }, { resource: 'v1' });
    expect((await api(env, agent, 'POST', '/v1/secrets/prod/A_KEY/fetch', {})).status).toBe(400);
    expect((await api(env, agent, 'POST', '/v1/secrets/prod/A_KEY/fetch', { reason: '  ' })).status).toBe(400);
    expect((await api(env, agent, 'POST', '/v1/secrets/..%2Fx/fetch', { reason: 'path traversal' })).status).toBe(400);
  });

  it('rate limits fetches per client', async () => {
    const agent = await connectAgent(env, owner, { folder: '' }, { resource: 'v1' });
    let last = 0;
    for (let i = 0; i < 61; i++) last = (await api(env, agent, 'POST', '/v1/secrets/prod/A_KEY/fetch', { reason: 'rate limit test' })).status;
    expect(last).toBe(429);
  });
});

describe('TOTP seed secrets', () => {
  it('give agents the current code and never the seed', async () => {
    const env = await startEnv();
    try {
      const o = await signInAs(env, 'owner@example.com');
      const owner = await browserFor(env, o.user, o.workspaceId);
      const seedValue = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
      await addSecret(env, o, { path: 'mfa/aws-root', value: seedValue, policy: 'open', kind: 'totp_seed' });
      await addSecret(env, o, { path: 'mfa/STATIC', value: 'plain', policy: 'open' });
      const agent = await connectAgent(env, owner, { folder: 'mfa' }, { resource: 'v1' });
      const res = await api(env, agent, 'POST', '/v1/secrets/mfa/aws-root/fetch', { reason: 'log in to AWS console' });
      expect(res.body.kind).toBe('totp');
      expect(res.body.code).toBe(await generate({ secret: seedValue, epoch: Math.floor(env.clock.now().getTime() / 1000) }));
      expect(JSON.stringify(res.body)).not.toContain(seedValue);
      expect(res.body.value).toBeUndefined();
    } finally {
      await env.close();
    }
  });
});

describe('audit log', () => {
  it('records actions without values or codes', async () => {
    const env = await startEnv();
    try {
      const o = await signInAs(env, 'owner@example.com');
      const seed = await enrollAuthenticator(env, o.user);
      const owner = await browserFor(env, await refreshUser(env, o.user), o.workspaceId);
      await addSecret(env, o, { path: 'prod/KEY', value: STRIPE, policy: 'approval' });
      const agent = await connectAgent(env, owner, { folder: '' }, { resource: 'v1' });
      const { body } = await api(env, agent, 'POST', '/v1/secrets/prod/KEY/fetch', { reason: 'audit test' });
      const code = await codeFor(env, seed);
      await form(env, owner, `/approvals/${body.request_id}/approve`, { code });
      await api(env, agent, 'POST', '/v1/secrets/prod/KEY/fetch', { reason: 'audit test', request_id: body.request_id });

      const rows = await env.ctx.db.query<Record<string, unknown>>('select * from audit_events order by at');
      const actions = rows.map(r => `${r.action}:${r.outcome}`);
      expect(actions).toEqual(expect.arrayContaining(['secret.create:success', 'grant.create:success', 'approval.request:pending', 'approval.approve:success', 'secret.fetch:success']));
      const dump = JSON.stringify(rows);
      expect(dump).not.toContain(STRIPE);
      expect(dump).not.toContain(code);
      expect(dump).not.toContain(agent.accessToken);
      expect(rows.find(r => r.action === 'secret.fetch' && r.outcome === 'success')).toMatchObject({ reason: 'audit test', secret_path: 'prod/KEY', actor_label: 'Test Agent' });

      // No plaintext anywhere in the database.
      const everything = JSON.stringify(await env.ctx.db.query('select * from secrets')) + JSON.stringify(await env.ctx.db.query('select * from users'));
      expect(everything).not.toContain(STRIPE);
      expect(everything).not.toContain(seed);
      const html = await (await page(env, owner, '/audit')).text();
      expect(html).toContain('approval.approve');
      expect(html).not.toContain(STRIPE);
    } finally {
      await env.close();
    }
  });
});
