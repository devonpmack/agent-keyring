import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { addSecret, browserFor, codeFor, connectAgent, enrollAuthenticator, form, refreshUser, signInAs, startEnv, type TestEnv } from './helpers.js';

describe('MCP server', () => {
  let env: TestEnv;
  let client: Client;
  let seed: string;
  let owner: Awaited<ReturnType<typeof browserFor>>;

  beforeEach(async () => {
    env = await startEnv();
    const o = await signInAs(env, 'owner@example.com');
    seed = await enrollAuthenticator(env, o.user);
    owner = await browserFor(env, await refreshUser(env, o.user), o.workspaceId);
    await addSecret(env, o, { path: 'prod/OPEN_KEY', value: 'open-fake', policy: 'open' });
    await addSecret(env, o, { path: 'prod/GUARDED', value: 'guarded-fake', policy: 'approval' });
    await addSecret(env, o, { path: 'mfa/site', value: 'JBSWY3DPEHPK3PXP', policy: 'open', kind: 'totp_seed' });
    const agent = await connectAgent(env, owner, { folder: '' }, { resource: 'mcp', clientName: 'Claude Code' });
    client = new Client({ name: 'test', version: '1' });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${env.baseUrl}/mcp`), { requestInit: { headers: { authorization: `Bearer ${agent.accessToken}` } } }));
  });
  afterEach(async () => {
    await client.close();
    await env.close();
  });

  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const res = await client.callTool({ name, arguments: args });
    const text = (res.content as { text: string }[])[0]!.text;
    return { isError: !!res.isError, body: JSON.parse(text) };
  };

  it('exposes only read tools', async () => {
    const { tools } = await client.listTools();
    expect(tools.map(t => t.name).sort()).toEqual(['get_secret', 'get_totp_code', 'list_secrets', 'request_approval']);
  });

  it('lists metadata without values', async () => {
    const { body } = await call('list_secrets');
    expect(body.secrets.map((s: { name: string }) => s.name)).toEqual(['mfa/site', 'prod/GUARDED', 'prod/OPEN_KEY']);
    expect(JSON.stringify(body)).not.toContain('fake');
  });

  it('runs the approval flow end to end', async () => {
    expect((await call('get_secret', { name: 'prod/OPEN_KEY', reason: 'run tests' })).body.value).toBe('open-fake');
    const pending = await call('get_secret', { name: 'prod/GUARDED', reason: 'deploy to prod' });
    expect(pending.body.status).toBe('pending_approval');
    expect(JSON.stringify(pending.body)).not.toContain('guarded-fake');
    await form(env, owner, `/approvals/${pending.body.request_id}/approve`, { code: await codeFor(env, seed) });
    const got = await call('get_secret', { name: 'prod/GUARDED', reason: 'deploy to prod', request_id: pending.body.request_id });
    expect(got.body.value).toBe('guarded-fake');
  });

  it('request_approval and get_totp_code behave', async () => {
    expect((await call('request_approval', { name: 'prod/OPEN_KEY', reason: 'just checking' })).body.status).toBe('not_required');
    expect((await call('request_approval', { name: 'prod/GUARDED', reason: 'need it soon' })).body.status).toBe('pending_approval');
    const totp = await call('get_totp_code', { name: 'mfa/site', reason: 'log in' });
    expect(totp.body.code).toMatch(/^\d{6}$/);
    expect(JSON.stringify(totp.body)).not.toContain('JBSWY3DPEHPK3PXP');
    const wrongKind = await call('get_totp_code', { name: 'prod/OPEN_KEY', reason: 'log in' });
    expect(wrongKind.isError).toBe(true);
  });

  it('returns structured errors for bad input', async () => {
    const res = await call('get_secret', { name: 'prod/OPEN_KEY', reason: '' });
    expect(res.isError).toBe(true);
    expect(res.body.error).toBe('invalid_input');
  });
});
