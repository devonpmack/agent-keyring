import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { addSecret, browserFor, codeFor, enrollAuthenticator, form, refreshUser, signInAs, startEnv, type Browser, type TestEnv } from './helpers.js';

// Runs the real CLI against a test server, playing the human in the browser.
describe('CLI', () => {
  let env: TestEnv;
  let home: string;
  let owner: Browser;
  let seed: string;

  beforeEach(async () => {
    env = await startEnv();
    home = mkdtempSync(join(tmpdir(), 'akr-cli-'));
    const o = await signInAs(env, 'owner@example.com');
    seed = await enrollAuthenticator(env, o.user);
    owner = await browserFor(env, await refreshUser(env, o.user), o.workspaceId);
    await addSecret(env, o, { path: 'ci/NPM_TOKEN', value: 'npm_FAKE_cli', policy: 'open' });
    await addSecret(env, o, { path: 'ci/DEPLOY_KEY', value: 'deploy_FAKE_cli', policy: 'approval' });
  });
  afterEach(async () => {
    await env.close();
    rmSync(home, { recursive: true, force: true });
  });

  function run(args: string[], onStderr?: (chunk: string) => void): Promise<{ code: number; stdout: string; stderr: string }> {
    return new Promise(resolve => {
      const child = spawn(process.execPath, ['--import', 'tsx', 'src/cli/index.ts', ...args], {
        env: { ...process.env, XDG_CONFIG_HOME: home, AGENT_KEYRING_NO_BROWSER: '1' },
      });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', d => (stdout += d));
      child.stderr.on('data', d => {
        stderr += d;
        onStderr?.(String(d));
      });
      child.on('close', code => resolve({ code: code ?? 1, stdout, stderr }));
    });
  }

  async function login() {
    let handled = false;
    const result = await run(['login', '--server', env.baseUrl], async chunk => {
      const match = chunk.match(/(http:\/\/localhost:\d+\/authorize\S+)/);
      if (!match || handled) return;
      handled = true;
      const consentPath = (await fetch(match[1]!, { redirect: 'manual' })).headers.get('location')!;
      const consent = await form(env, owner, consentPath, { decision: 'approve', workspaceId: owner.workspaceId, folder: 'ci' });
      await fetch(consent.headers.get('location')!);
    });
    expect(result.stderr).toContain('Signed in');
    expect(result.code).toBe(0);
  }

  it('logs in with the browser flow and reads secrets', async () => {
    await login();
    expect(statSync(join(home, 'agent-keyring', 'credentials.json')).mode & 0o777).toBe(0o600);
    const list = await run(['list']);
    expect(list.stdout).toContain('ci/NPM_TOKEN\topen');
    expect(list.stdout).not.toContain('npm_FAKE_cli');
    const got = await run(['get', 'ci/NPM_TOKEN', '--reason', 'publish package']);
    expect(got.stdout).toBe('npm_FAKE_cli');
  });

  it('waits for approval and prints the approval URL', async () => {
    await login();
    const noWait = await run(['get', 'ci/DEPLOY_KEY', '--reason', 'deploy', '--no-wait']);
    expect(noWait.code).toBe(2);
    expect(noWait.stderr).toContain('/approvals/');
    expect(noWait.stdout).toBe('');

    let approved = false;
    const waiting = await run(['get', 'ci/DEPLOY_KEY', '--reason', 'deploy now'], async chunk => {
      const id = chunk.match(/request ([0-9A-Z]{10})/)?.[1];
      if (!id || approved) return;
      approved = true;
      env.clock.advance(30);
      await form(env, owner, `/approvals/${id}/approve`, { code: await codeFor(env, seed) });
    });
    expect(waiting.stdout).toBe('deploy_FAKE_cli');
  });

  it('logout revokes the device', async () => {
    await login();
    await run(['logout']);
    const [grant] = await env.ctx.db.query<{ revoked_at: Date | null }>('select revoked_at from grants');
    expect(grant?.revoked_at).not.toBeNull();
    expect((await run(['list'])).code).toBe(1);
  });
});
