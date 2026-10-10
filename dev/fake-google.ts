import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

// A stand-in for Google's OpenID provider, for local development and tests
// only. Tests queue an identity and /authorize redirects straight back; when
// nothing is queued it shows a form to type any email address.
export type FakeIdentity = { sub: string; email: string; email_verified: boolean; name: string; auth_time?: number };

export async function startFakeGoogle(clientId: string, port = 0) {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
  const codes = new Map<string, { nonce: string; identity: FakeIdentity }>();
  const state = { next: undefined as FakeIdentity | undefined, lastAuthorize: undefined as URLSearchParams | undefined };
  let issuer = '';

  const server: Server = createServer(async (req, res) => {
    const url = new URL(req.url!, issuer);
    const json = (body: unknown) => res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(body));
    if (url.pathname === '/.well-known/openid-configuration') {
      return json({
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        code_challenge_methods_supported: ['S256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
      });
    }
    if (url.pathname === '/jwks') return json({ keys: [jwk] });
    if (url.pathname === '/authorize') {
      state.lastAuthorize = url.searchParams;
      let identity = state.next;
      const typed = url.searchParams.get('login_email');
      if (typed) identity = { sub: 'dev-' + typed.toLowerCase(), email: typed, email_verified: true, name: typed.split('@')[0]!, auth_time: Math.floor(Date.now() / 1000) };
      if (!identity) return res.writeHead(200, { 'content-type': 'text/html' }).end(loginForm(url.searchParams));
      const code = Math.random().toString(36).slice(2);
      codes.set(code, { nonce: url.searchParams.get('nonce')!, identity });
      const back = new URL(url.searchParams.get('redirect_uri')!);
      back.searchParams.set('code', code);
      back.searchParams.set('state', url.searchParams.get('state')!);
      return res.writeHead(302, { location: back.href }).end();
    }
    if (url.pathname === '/token') {
      let body = '';
      for await (const chunk of req) body += chunk;
      const entry = codes.get(new URLSearchParams(body).get('code')!);
      if (!entry) return res.writeHead(400, { 'content-type': 'application/json' }).end('{"error":"invalid_grant"}');
      const now = Math.floor(Date.now() / 1000);
      const idToken = await new SignJWT({ ...entry.identity, nonce: entry.nonce })
        .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
        .setIssuer(issuer)
        .setAudience(clientId)
        .setSubject(entry.identity.sub)
        .setIssuedAt(now)
        .setExpirationTime(now + 300)
        .sign(privateKey);
      return json({ access_token: 'fake-access', token_type: 'Bearer', expires_in: 300, id_token: idToken });
    }
    res.writeHead(404).end();
  });
  await new Promise<void>(resolve => server.listen(port, port ? '0.0.0.0' : '127.0.0.1', resolve));
  issuer = process.env.FAKE_GOOGLE_ISSUER ?? `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    issuer,
    state,
    close: () => new Promise(resolve => server.close(resolve)),
  };
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
}

function loginForm(params: URLSearchParams): string {
  const hidden = [...params].map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`).join('');
  return `<!doctype html><meta name="viewport" content="width=device-width"><title>Fake Google (dev)</title>
<body style="font-family:system-ui;max-width:420px;margin:15vh auto;padding:0 16px">
<h1>Fake Google sign-in</h1><p>Development only. Type any email address.</p>
<form method="get" action="/authorize">${hidden}<input name="login_email" type="email" required autofocus placeholder="owner@example.com" style="font:inherit;padding:8px;width:100%">
<p><button style="font:inherit;padding:8px 16px">Sign in</button></p></form>`;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 8091);
  const google = await startFakeGoogle(process.env.GOOGLE_CLIENT_ID ?? 'dev-client', port);
  console.log(`fake Google issuer at ${google.issuer}`);
}
