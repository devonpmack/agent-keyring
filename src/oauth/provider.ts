import { randomUUID } from 'node:crypto';
import type { Response } from 'express';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import { InvalidClientMetadataError, InvalidGrantError, InvalidRequestError, InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { AuthorizationParams, OAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { OAuthClientInformationFull, OAuthTokenRevocationRequest, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import { hashToken, humanId, randomToken } from '../crypto/tokens.js';
import { audit } from '../domain/audit.js';
import type { AppContext } from '../domain/context.js';
import { addSeconds } from '../domain/context.js';
import { clientDisplayName, type ClientMetadata, type Grant } from '../domain/grants.js';

export const ACCESS_TOKEN_TTL = 10 * 60;
export const REFRESH_TOKEN_TTL = 30 * 24 * 60 * 60;
const AUTHORIZATION_TTL = 10 * 60;

export function resourcesOf(ctx: Pick<AppContext, 'config'>) {
  return { mcp: `${ctx.config.baseUrl}/mcp`, api: `${ctx.config.baseUrl}/v1` };
}

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

// https anywhere, http only on loopback (RFC 8252), or a private-use scheme
// such as cursor:// for native apps. Script-capable schemes are refused.
function acceptableRedirect(uri: string): boolean {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return false;
  }
  if (url.hash) return false;
  if (url.protocol === 'https:') return true;
  if (url.protocol === 'http:') return LOOPBACK.has(url.hostname);
  return /^[a-z][a-z0-9+.-]*:$/.test(url.protocol) && !['javascript:', 'data:', 'file:', 'vbscript:', 'blob:', 'about:'].includes(url.protocol);
}

type TokenRow = { token_hash: string; kind: 'access' | 'refresh'; grant_id: string; client_id: string; resource: string; expires_at: Date; used_at: Date | null; revoked_at: Date | null };

export class KeyringOAuthProvider implements OAuthServerProvider {
  constructor(private readonly ctx: AppContext) {}

  get clientsStore(): OAuthRegisteredClientsStore {
    const ctx = this.ctx;
    return {
      async getClient(clientId: string) {
        const [row] = await ctx.db.query<{ metadata: OAuthClientInformationFull }>('select metadata from oauth_clients where client_id = $1', [clientId]);
        return row?.metadata;
      },
      // Only public clients (PKCE, no client secret) are issued, so no client
      // secret is ever stored. RFC 7591 lets the server override requested values.
      async registerClient(client) {
        if (client.redirect_uris.length === 0 || client.redirect_uris.length > 10 || !client.redirect_uris.every(acceptableRedirect)) {
          throw new InvalidClientMetadataError('redirect_uris must be https, http on loopback, or a private-use scheme');
        }
        const full: OAuthClientInformationFull = {
          ...client,
          client_name: client.client_name?.slice(0, 100),
          client_id: randomUUID(),
          client_id_issued_at: Math.floor(ctx.clock.now().getTime() / 1000),
          token_endpoint_auth_method: 'none',
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
          client_secret: undefined,
          client_secret_expires_at: undefined,
        };
        await ctx.db.query('insert into oauth_clients (client_id, metadata, created_at) values ($1, $2, $3)', [full.client_id, JSON.stringify(full), ctx.clock.now()]);
        await audit(ctx, { workspaceId: null, actor: { type: 'client', id: full.client_id, label: clientDisplayName(full.client_id, full as ClientMetadata) }, action: 'client.register', outcome: 'success', detail: { redirect_uris: full.redirect_uris } });
        return full;
      },
    };
  }

  // Parks the request and sends the browser to the consent page, where a
  // signed-in human picks the workspace and folder (or denies).
  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    const resources = Object.values(resourcesOf(this.ctx));
    const resource = params.resource?.href.replace(/\/$/, '') ?? resourcesOf(this.ctx).mcp;
    if (!resources.includes(resource)) throw new InvalidRequestError('Unknown resource');
    const id = humanId(16);
    const now = this.ctx.clock.now();
    await this.ctx.db.query(
      `insert into oauth_authorizations (id, client_id, redirect_uri, code_challenge, state, resource, created_at, expires_at)
       values ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [id, client.client_id, params.redirectUri, params.codeChallenge, params.state ?? null, resource, now, addSeconds(now, AUTHORIZATION_TTL)],
    );
    res.redirect(302, `/oauth/consent/${id}`);
  }

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, code: string): Promise<string> {
    const [row] = await this.ctx.db.query<{ code_challenge: string; client_id: string }>('select code_challenge, client_id from oauth_codes where code_hash = $1', [hashToken(code)]);
    if (!row || row.client_id !== client.client_id) throw new InvalidGrantError('Invalid authorization code');
    return row.code_challenge;
  }

  async exchangeAuthorizationCode(client: OAuthClientInformationFull, code: string, _verifier?: string, redirectUri?: string, resource?: URL): Promise<OAuthTokens> {
    const now = this.ctx.clock.now();
    const [row] = await this.ctx.db.query<{ grant_id: string; client_id: string; redirect_uri: string; resource: string; expires_at: Date; used_at: Date | null }>(
      'select grant_id, client_id, redirect_uri, resource, expires_at, used_at from oauth_codes where code_hash = $1',
      [hashToken(code)],
    );
    if (!row || row.client_id !== client.client_id) throw new InvalidGrantError('Invalid authorization code');
    if (row.used_at) {
      // A replayed code means it leaked; kill everything it produced (RFC 6749 §4.1.2).
      await this.revokeGrantInternal(row.grant_id, 'code_reuse');
      throw new InvalidGrantError('Authorization code already used');
    }
    if (row.expires_at <= now) throw new InvalidGrantError('Authorization code expired');
    if (redirectUri !== undefined && redirectUri !== row.redirect_uri) throw new InvalidGrantError('redirect_uri mismatch');
    if (resource && resource.href.replace(/\/$/, '') !== row.resource) throw new InvalidGrantError('resource mismatch');
    const claimed = await this.ctx.db.query('update oauth_codes set used_at = $2 where code_hash = $1 and used_at is null returning code_hash', [hashToken(code), now]);
    if (claimed.length !== 1) throw new InvalidGrantError('Authorization code already used');
    return this.issueTokens(row.grant_id, client.client_id, row.resource);
  }

  async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string, _scopes?: string[], resource?: URL): Promise<OAuthTokens> {
    const now = this.ctx.clock.now();
    const row = await this.findToken(refreshToken, 'refresh');
    if (!row || row.client_id !== client.client_id) throw new InvalidGrantError('Invalid refresh token');
    if (row.used_at) {
      // Rotation reuse: either the client or an attacker holds a stale copy.
      await this.revokeGrantInternal(row.grant_id, 'refresh_reuse');
      throw new InvalidGrantError('Refresh token already used; grant revoked');
    }
    if (row.revoked_at || row.expires_at <= now || !(await this.activeGrant(row.grant_id))) throw new InvalidGrantError('Refresh token is no longer valid');
    if (resource && resource.href.replace(/\/$/, '') !== row.resource) throw new InvalidGrantError('resource mismatch');
    const claimed = await this.ctx.db.query('update oauth_tokens set used_at = $2 where token_hash = $1 and used_at is null returning token_hash', [row.token_hash, now]);
    if (claimed.length !== 1) throw new InvalidGrantError('Refresh token already used');
    return this.issueTokens(row.grant_id, client.client_id, row.resource);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const row = await this.findToken(token, 'access');
    const now = this.ctx.clock.now();
    if (!row || row.revoked_at || row.expires_at <= now) throw new InvalidTokenError('Invalid or expired access token');
    const grant = await this.activeGrant(row.grant_id);
    if (!grant) throw new InvalidTokenError('Access was revoked');
    await this.ctx.db.query('update grants set last_used_at = $2 where id = $1', [grant.id, now]);
    return {
      token,
      clientId: row.client_id,
      scopes: [],
      expiresAt: Math.floor(row.expires_at.getTime() / 1000),
      resource: new URL(row.resource),
      extra: { grantId: grant.id },
    };
  }

  // Revoking a refresh token ends the whole grant (the client is logging out);
  // revoking an access token ends just that token.
  async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    const [row] = await this.ctx.db.query<TokenRow>('select * from oauth_tokens where token_hash = $1 and client_id = $2', [hashToken(request.token), client.client_id]);
    if (!row) return;
    if (row.kind === 'refresh') {
      await this.revokeGrantInternal(row.grant_id, 'client_revoked');
      return;
    }
    await this.ctx.db.query('update oauth_tokens set revoked_at = $2 where token_hash = $1', [row.token_hash, this.ctx.clock.now()]);
  }

  private async findToken(token: string, kind: TokenRow['kind']): Promise<TokenRow | undefined> {
    const [row] = await this.ctx.db.query<TokenRow>('select * from oauth_tokens where token_hash = $1 and kind = $2', [hashToken(token), kind]);
    return row;
  }

  private async activeGrant(grantId: string): Promise<Grant | undefined> {
    const [grant] = await this.ctx.db.query<Grant>('select * from grants where id = $1 and revoked_at is null', [grantId]);
    return grant;
  }

  private async issueTokens(grantId: string, clientId: string, resource: string): Promise<OAuthTokens> {
    const now = this.ctx.clock.now();
    const access = randomToken('akat_');
    const refresh = randomToken('akrt_');
    await this.ctx.db.tx(async q => {
      const insert = `insert into oauth_tokens (token_hash, kind, grant_id, client_id, resource, created_at, expires_at) values ($1,$2,$3,$4,$5,$6,$7)`;
      await q.query(insert, [hashToken(access), 'access', grantId, clientId, resource, now, addSeconds(now, ACCESS_TOKEN_TTL)]);
      await q.query(insert, [hashToken(refresh), 'refresh', grantId, clientId, resource, now, addSeconds(now, REFRESH_TOKEN_TTL)]);
    });
    return { access_token: access, token_type: 'Bearer', expires_in: ACCESS_TOKEN_TTL, refresh_token: refresh };
  }

  private async revokeGrantInternal(grantId: string, why: 'code_reuse' | 'refresh_reuse' | 'client_revoked'): Promise<void> {
    const [grant] = await this.ctx.db.query<Grant & { metadata: ClientMetadata }>(
      `update grants g set revoked_at = $2 from oauth_clients c
       where g.id = $1 and g.revoked_at is null and c.client_id = g.client_id returning g.*, c.metadata`,
      [grantId, this.ctx.clock.now()],
    );
    if (!grant) return;
    const clientName = clientDisplayName(grant.client_id, grant.metadata);
    await audit(this.ctx, { workspaceId: grant.workspace_id, actor: { type: 'system', label: 'agent-keyring' }, action: 'grant.revoke', outcome: 'success', grantId, detail: { why, client: clientName } });
    if (why !== 'client_revoked') {
      await this.ctx.notifier.notify({ type: 'token_reuse', workspaceId: grant.workspace_id, grantId, clientName, why });
    }
  }
}
