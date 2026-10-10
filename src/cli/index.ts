#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { auth, type OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js';
import type { OAuthClientInformationMixed, OAuthClientMetadata, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';

// The CLI is just another OAuth client: it registers itself dynamically, signs
// in through the browser with PKCE and a loopback redirect (RFC 8252), and
// keeps its tokens in a 0600 file under ~/.config/agent-keyring.

type Stored = { server?: string; client?: OAuthClientInformationMixed; tokens?: OAuthTokens; verifier?: string };

const dir = join(process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config'), 'agent-keyring');
const file = join(dir, 'credentials.json');

function load(): Stored {
  if (!existsSync(file)) return {};
  return JSON.parse(readFileSync(file, 'utf8')) as Stored;
}

function save(data: Stored): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeFileSync(file, JSON.stringify(data, null, 2), { mode: 0o600 });
  chmodSync(file, 0o600);
}

class CliOAuthProvider implements OAuthClientProvider {
  private expectedState = randomBytes(16).toString('base64url');
  constructor(
    private data: Stored,
    private readonly redirect: string | undefined,
    private readonly onRedirect: (url: URL) => void = () => {
      throw new Error('Not signed in. Run: agent-keyring login');
    },
  ) {}

  get redirectUrl() {
    return this.redirect;
  }
  get clientMetadata(): OAuthClientMetadata {
    return { client_name: 'agent-keyring CLI', redirect_uris: [this.redirect ?? 'http://127.0.0.1/callback'], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none' };
  }
  state() {
    return this.expectedState;
  }
  checkState(state: string | null) {
    return state === this.expectedState;
  }
  clientInformation() {
    return this.data.client;
  }
  saveClientInformation(client: OAuthClientInformationMixed) {
    this.data = { ...this.data, client };
    save(this.data);
  }
  tokens() {
    return this.data.tokens;
  }
  saveTokens(tokens: OAuthTokens) {
    this.data = { ...this.data, tokens };
    save(this.data);
  }
  redirectToAuthorization(url: URL) {
    this.onRedirect(url);
  }
  saveCodeVerifier(verifier: string) {
    this.data = { ...this.data, verifier };
  }
  codeVerifier() {
    if (!this.data.verifier) throw new Error('No PKCE verifier');
    return this.data.verifier;
  }
  invalidateCredentials(scope: 'all' | 'client' | 'tokens' | 'verifier' | 'discovery') {
    if (scope === 'all' || scope === 'tokens') this.data = { ...this.data, tokens: undefined };
    if (scope === 'all' || scope === 'client') this.data = { ...this.data, client: undefined };
    save(this.data);
  }
}

function browserCommand(): string {
  if (process.platform === 'darwin') return 'open';
  if (process.platform === 'win32') return 'explorer';
  return 'xdg-open';
}

function openBrowser(url: string): void {
  // Headless machines (and the test suite) open the printed URL themselves.
  if (process.env.AGENT_KEYRING_NO_BROWSER) return;
  spawn(browserCommand(), [url], { stdio: 'ignore', detached: true }).on('error', () => {}).unref();
}

async function login(server: string): Promise<void> {
  const previous = load();
  const data: Stored = { server: server.replace(/\/$/, '') };
  // Reuse the registered client when signing in to the same server again.
  if (previous.server === data.server) data.client = previous.client;
  const resource = `${data.server}/v1`;

  const callback = createServer();
  await new Promise<void>(resolve => callback.listen(0, '127.0.0.1', resolve));
  const redirect = `http://127.0.0.1:${(callback.address() as AddressInfo).port}/callback`;
  const provider = new CliOAuthProvider(data, redirect, url => {
    process.stderr.write(`Opening your browser to sign in:\n  ${url.href}\n`);
    openBrowser(url.href);
  });

  const code = new Promise<string>((resolve, reject) => {
    callback.on('request', (req, res) => {
      const url = new URL(req.url ?? '/', redirect);
      if (url.pathname !== '/callback') return res.writeHead(404).end();
      const error = url.searchParams.get('error');
      const value = url.searchParams.get('code');
      if (error || !value || !provider.checkState(url.searchParams.get('state'))) {
        res.writeHead(400, { 'content-type': 'text/plain' }).end('Sign-in failed. You can close this tab.');
        return reject(new Error(error ? `Sign-in failed: ${error}` : 'Sign-in failed: bad callback'));
      }
      res.writeHead(200, { 'content-type': 'text/plain' }).end('Signed in to agent-keyring. You can close this tab.');
      resolve(value);
    });
  });

  try {
    if ((await auth(provider, { serverUrl: resource })) === 'AUTHORIZED') return;
    const timeout = new Promise<never>((_, reject) => setTimeout(() => reject(new Error('Timed out waiting for sign-in')), 5 * 60_000).unref());
    await auth(provider, { serverUrl: resource, authorizationCode: await Promise.race([code, timeout]) });
    process.stderr.write(`Signed in to ${data.server}\n`);
  } finally {
    callback.close();
  }
}

async function call(method: string, path: string, body?: unknown): Promise<{ status: number; body: any }> {
  let data = load();
  if (!data.server || !data.tokens) throw new Error('Not signed in. Run: agent-keyring login --server https://your-keyring');
  const send = (token: string) =>
    fetch(`${data.server}${path}`, {
      method,
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  let res = await send(data.tokens!.access_token);
  if (res.status === 401) {
    // Access tokens live 10 minutes; the SDK refreshes with the stored refresh token.
    const provider = new CliOAuthProvider(data, undefined);
    await auth(provider, { serverUrl: `${data.server}/v1` });
    data = load();
    res = await send(data.tokens!.access_token);
  }
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

function fail(body: { error?: string; message?: string }): never {
  process.stderr.write(`error: ${body.message ?? body.error ?? 'request failed'}\n`);
  process.exit(1);
}

async function get(name: string, reason: string, opts: { code?: string; wait: boolean }): Promise<void> {
  const path = `/v1/secrets/${name.split('/').map(encodeURIComponent).join('/')}/fetch`;
  let res = await call('POST', path, { reason });
  if (res.body.status === 'pending_approval') {
    const requestId = res.body.request_id as string;
    if (opts.code) {
      res = await call('POST', path, { reason, request_id: requestId, totp_code: opts.code });
    } else {
      process.stderr.write(`Approval needed for ${res.body.name} (request ${requestId}).\nApprove at: ${res.body.approval_url}\n`);
      if (!opts.wait) process.exit(2);
      const deadline = Date.parse(res.body.expires_at);
      while (res.body.status === 'pending_approval' && Date.now() < deadline) {
        await new Promise(r => setTimeout(r, 2000));
        res = await call('POST', path, { reason, request_id: requestId });
      }
    }
  }
  if (res.body.status !== 'ok') fail(res.body);
  process.stdout.write((res.body.kind === 'totp' ? res.body.code : res.body.value) + (process.stdout.isTTY ? '\n' : ''));
}

async function logout(): Promise<void> {
  const data = load();
  if (data.server && data.tokens?.refresh_token && data.client) {
    await fetch(`${data.server}/revoke`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: data.tokens.refresh_token, token_type_hint: 'refresh_token', client_id: data.client.client_id }).toString(),
    }).catch(() => {});
  }
  rmSync(file, { force: true });
  process.stderr.write('Signed out and revoked this device.\n');
}

const USAGE = `agent-keyring — secrets for AI agents, with human approval where it matters

Usage:
  agent-keyring login --server <url>     Sign in through the browser
  agent-keyring list                     List secrets you can access (no values)
  agent-keyring get <path> --reason <r>  Print a secret (or current TOTP code) to stdout
      --code <123456>                    Approve with an authenticator code, if the secret allows it
      --no-wait                          Exit with status 2 instead of waiting for approval
  agent-keyring logout                   Revoke this device and delete local credentials
`;

async function main(): Promise<void> {
  const { positionals, values } = parseArgs({
    allowPositionals: true,
    options: {
      server: { type: 'string' },
      reason: { type: 'string', short: 'r' },
      code: { type: 'string' },
      'no-wait': { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
  });
  const [command, arg] = positionals;
  if (values.help || !command) return void process.stdout.write(USAGE);
  switch (command) {
    case 'login': {
      const server = values.server ?? load().server ?? process.env.AGENT_KEYRING_URL;
      if (!server) throw new Error('Pass --server https://your-keyring');
      return login(server);
    }
    case 'list': {
      const res = await call('GET', '/v1/secrets');
      if (res.status !== 200) fail(res.body);
      for (const s of res.body.secrets as { name: string; policy: string; kind: string }[]) {
        process.stdout.write(`${s.name}\t${s.policy}${s.kind === 'totp_seed' ? '\ttotp' : ''}\n`);
      }
      return;
    }
    case 'get': {
      if (!arg) throw new Error('Usage: agent-keyring get <path> --reason "why"');
      if (!values.reason) throw new Error('--reason is required; it is shown to the human who approves');
      return get(arg, values.reason, { code: values.code, wait: !values['no-wait'] });
    }
    case 'logout':
      return logout();
    default:
      process.stdout.write(USAGE);
      process.exit(1);
  }
}

main().catch(err => {
  process.stderr.write(`error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
