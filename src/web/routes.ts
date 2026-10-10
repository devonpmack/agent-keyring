import express, { Router, type Request, type Response } from 'express';
import QRCode from 'qrcode';
import { z } from 'zod';
import { approveWithPasskey, approveWithTotp, denyApproval, getApprovalView, listApprovals } from '../domain/approvals.js';
import { listAudit } from '../domain/audit.js';
import type { AppContext } from '../domain/context.js';
import { AppError } from '../domain/errors.js';
import { listGrants, revokeGrant } from '../domain/grants.js';
import { joinPath } from '../domain/paths.js';
import {
  approvalOptions,
  deletePasskey,
  finishRegistration,
  listPasskeys,
  registrationOptions,
  verifyApprovalAssertion,
  type Challenge,
} from '../domain/passkeys.js';
import { createSecret, deleteSecret, foldersOf, getSecret, listSecrets, updateSecret } from '../domain/secrets.js';
import { confirmEnrollment, startEnrollment } from '../domain/totp.js';
import { addMember, listMembers, listMemberships, removeMember, roleIn } from '../domain/users.js';
import { approveAuthorization, denyAuthorization, getAuthorization } from '../oauth/consent.js';
import { resourcesOf } from '../oauth/provider.js';
import { destroySession, requireOwner, requireRecentAuth, requireUser, safeReturnTo, verifyCsrf, type Session } from './session.js';
import * as views from './views.js';

const formBool = z.preprocess(v => v === '1' || v === 'on' || v === true, z.boolean());

export function webRouter(ctx: AppContext): Router {
  const router = Router();
  const recent = requireRecentAuth(ctx);
  router.use(express.urlencoded({ extended: false, limit: '100kb' }));
  router.use(express.json({ limit: '50kb' }));
  router.use(verifyCsrf(ctx));

  const session = (req: Request): Session => req.session!;

  async function chrome(req: Request, extra: Partial<views.PageChrome> = {}): Promise<views.PageChrome> {
    const s = session(req);
    const [memberships, pending] = await Promise.all([
      listMemberships(ctx, s.user.id),
      ctx.db.query<{ n: number }>(`select count(*)::int as n from approval_requests where workspace_id = $1 and status = 'pending' and expires_at > $2`, [s.workspaceId, ctx.clock.now()]),
    ]);
    const flash = typeof req.query.flash === 'string' ? req.query.flash.slice(0, 200) : undefined;
    return { session: s, memberships, pendingCount: pending[0]?.n ?? 0, flash, ...extra };
  }

  const send = (res: Response, page: string) => res.type('html').send(page);
  const back = (res: Response, path: string, flash: string) => res.redirect(303, `${path}?flash=${encodeURIComponent(flash)}`);

  router.get('/login', (req, res) => {
    if (req.session) return res.redirect(302, safeReturnTo(req.query.return_to));
    send(res, views.loginPage(safeReturnTo(req.query.return_to)));
  });

  router.post('/logout', requireUser, async (req, res) => {
    await destroySession(ctx, req, res);
    res.redirect(303, '/login');
  });

  router.post('/workspace', requireUser, async (req, res) => {
    const workspaceId = z.uuid().parse(req.body.workspaceId);
    if (!(await roleIn(ctx, session(req).user.id, workspaceId))) throw new AppError('forbidden', 'Not a member of that workspace', 403);
    await ctx.db.query('update sessions set workspace_id = $2 where id_hash = $1', [session(req).idHash, workspaceId]);
    res.redirect(303, '/');
  });

  // ---- Secrets ----

  router.get('/', requireUser, async (req, res) => {
    const secrets = await listSecrets(ctx, session(req).workspaceId);
    const folder = typeof req.query.folder === 'string' ? req.query.folder : undefined;
    send(res, views.secretsPage(await chrome(req), secrets, foldersOf(secrets), folder));
  });

  router.get('/secrets/new', requireUser, recent, async (req, res) => {
    const folders = foldersOf(await listSecrets(ctx, session(req).workspaceId));
    send(res, views.newSecretPage(await chrome(req), typeof req.query.folder === 'string' ? req.query.folder : '', folders));
  });

  router.post('/secrets', requireUser, recent, async (req, res) => {
    const s = session(req);
    const created = await createSecret(ctx, s.user, s.workspaceId, {
      folder: req.body.folder ?? '',
      name: req.body.name,
      kind: req.body.kind,
      value: req.body.value,
      notes: req.body.notes,
      tags: req.body.tags,
      policy: req.body.policy,
      allowChatApproval: formBool.parse(req.body.allowChatApproval),
    });
    back(res, `/secrets/${created.id}`, `Saved ${joinPath(created.folder, created.name)}`);
  });

  router.get('/secrets/:id', requireUser, async (req, res) => {
    const s = session(req);
    const secret = await getSecret(ctx, s.workspaceId, z.uuid().parse(req.params.id));
    const recentEvents = await listAudit(ctx, s.workspaceId, { secret: joinPath(secret.folder, secret.name), limit: 20 });
    send(res, views.secretPage(await chrome(req), secret, recentEvents));
  });

  router.post('/secrets/:id', requireUser, recent, async (req, res) => {
    const s = session(req);
    const id = z.uuid().parse(req.params.id);
    await updateSecret(ctx, s.user, s.workspaceId, id, {
      value: req.body.value || undefined,
      notes: req.body.notes,
      tags: req.body.tags,
      policy: req.body.policy,
      allowChatApproval: formBool.parse(req.body.allowChatApproval),
    });
    back(res, `/secrets/${id}`, 'Saved');
  });

  router.post('/secrets/:id/delete', requireUser, recent, async (req, res) => {
    const s = session(req);
    await deleteSecret(ctx, s.user, s.workspaceId, z.uuid().parse(req.params.id));
    back(res, '/', 'Secret deleted');
  });

  // ---- Approvals ----

  router.get('/approvals', requireUser, async (req, res) => {
    send(res, views.approvalsPage(await chrome(req), await listApprovals(ctx, session(req).workspaceId)));
  });

  const approvalId = (req: Request) => z.string().regex(/^[0-9A-Z]{10}$/).parse(req.params.id);

  router.get('/approvals/:id', requireUser, async (req, res) => {
    const s = session(req);
    const view = await getApprovalView(ctx, s.workspaceId, approvalId(req));
    const passkeys = await listPasskeys(ctx, s.user.id);
    send(res, views.approvalPage(await chrome(req), view, { hasAuthenticator: !!s.user.totp_enrolled_at, hasPasskey: passkeys.length > 0 }));
  });

  router.post('/approvals/:id/approve', requireUser, async (req, res) => {
    const s = session(req);
    const id = approvalId(req);
    try {
      await approveWithTotp(ctx, s.user, s.workspaceId, id, String(req.body.code ?? ''), 'totp_web', req.ip);
    } catch (err) {
      if (!(err instanceof AppError) || (err.code !== 'invalid_code' && err.code !== 'locked')) throw err;
      const view = await getApprovalView(ctx, s.workspaceId, id);
      const passkeys = await listPasskeys(ctx, s.user.id);
      return send(res.status(err.status), views.approvalPage(await chrome(req, { error: err.message }), view, { hasAuthenticator: true, hasPasskey: passkeys.length > 0 }));
    }
    back(res, `/approvals/${id}`, 'Approved. The agent can fetch the secret once.');
  });

  router.post('/approvals/:id/deny', requireUser, async (req, res) => {
    const s = session(req);
    const id = approvalId(req);
    await denyApproval(ctx, s.user, s.workspaceId, id, req.ip);
    back(res, `/approvals/${id}`, 'Denied');
  });

  const saveChallenge = (s: Session, challenge: Challenge | null) =>
    ctx.db.query('update sessions set webauthn_challenge = $2 where id_hash = $1', [s.idHash, challenge ? JSON.stringify(challenge) : null]);

  router.post('/approvals/:id/passkey/options', requireUser, async (req, res) => {
    const s = session(req);
    const id = approvalId(req);
    await getApprovalView(ctx, s.workspaceId, id);
    const { options, challenge } = await approvalOptions(ctx, s.user, id);
    await saveChallenge(s, challenge);
    res.json(options);
  });

  router.post('/approvals/:id/passkey/verify', requireUser, async (req, res) => {
    const s = session(req);
    const id = approvalId(req);
    await saveChallenge(s, null);
    await verifyApprovalAssertion(ctx, s.user, id, s.webauthnChallenge, req.body);
    await approveWithPasskey(ctx, s.user, s.workspaceId, id, req.ip);
    res.json({ ok: true, redirect: `/approvals/${id}?flash=${encodeURIComponent('Approved with passkey.')}` });
  });

  // ---- Agents ----

  router.get('/agents', requireUser, async (req, res) => {
    send(res, views.agentsPage(await chrome(req), await listGrants(ctx, session(req).workspaceId), resourcesOf(ctx).mcp));
  });

  router.post('/agents/:id/revoke', requireUser, recent, async (req, res) => {
    const s = session(req);
    await revokeGrant(ctx, s.user, s.workspaceId, z.uuid().parse(req.params.id));
    back(res, '/agents', 'Access revoked');
  });

  // ---- Audit ----

  router.get('/audit', requireUser, async (req, res) => {
    const filter = {
      action: typeof req.query.action === 'string' && req.query.action ? req.query.action.slice(0, 50) : undefined,
      secret: typeof req.query.secret === 'string' && req.query.secret ? req.query.secret.slice(0, 600) : undefined,
    };
    const before = typeof req.query.before === 'string' ? new Date(req.query.before) : undefined;
    const rows = await listAudit(ctx, session(req).workspaceId, { ...filter, before: before && !isNaN(before.getTime()) ? before : undefined, limit: 100 });
    send(res, views.auditPage(await chrome(req), rows, filter));
  });

  // ---- Settings: authenticator and passkeys ----

  router.get('/settings', requireUser, async (req, res) => {
    const s = session(req);
    send(res, views.settingsPage(await chrome(req), { enrolledAt: s.user.totp_enrolled_at, passkeys: await listPasskeys(ctx, s.user.id) }));
  });

  router.post('/settings/authenticator', requireUser, recent, async (req, res) => {
    const s = session(req);
    const { uri, secret } = await startEnrollment(ctx, s.user);
    const qr = await QRCode.toDataURL(uri, { margin: 1, width: 200 });
    res.set('Cache-Control', 'no-store');
    send(res, views.settingsPage(await chrome(req), { enrolledAt: s.user.totp_enrolled_at, enrollment: { qr, secret }, passkeys: await listPasskeys(ctx, s.user.id) }));
  });

  router.post('/settings/authenticator/confirm', requireUser, recent, async (req, res) => {
    await confirmEnrollment(ctx, session(req).user, String(req.body.code ?? ''), session(req).workspaceId);
    back(res, '/settings', 'Authenticator enrolled');
  });

  router.post('/settings/passkeys/options', requireUser, recent, async (req, res) => {
    const s = session(req);
    const { options, challenge } = await registrationOptions(ctx, s.user);
    await saveChallenge(s, challenge);
    res.json(options);
  });

  router.post('/settings/passkeys/verify', requireUser, recent, async (req, res) => {
    const s = session(req);
    await saveChallenge(s, null);
    const body = z.object({ name: z.string().max(60).default('Passkey'), response: z.any() }).parse(req.body);
    await finishRegistration(ctx, s.user, s.workspaceId, s.webauthnChallenge, body.response, body.name);
    res.json({ ok: true, redirect: `/settings?flash=${encodeURIComponent('Passkey added')}` });
  });

  router.post('/settings/passkeys/:id/delete', requireUser, recent, async (req, res) => {
    await deletePasskey(ctx, session(req).user, session(req).workspaceId, String(req.params.id));
    back(res, '/settings', 'Passkey removed');
  });

  // ---- Members (allowlist) ----

  router.get('/members', requireUser, requireOwner, async (req, res) => {
    send(res, views.membersPage(await chrome(req), await listMembers(ctx, session(req).workspaceId), ctx.config.mode));
  });

  router.post('/members', requireUser, requireOwner, recent, async (req, res) => {
    const s = session(req);
    await addMember(ctx, s.user, s.workspaceId, String(req.body.email ?? ''));
    back(res, '/members', 'Added');
  });

  router.post('/members/remove', requireUser, requireOwner, recent, async (req, res) => {
    const s = session(req);
    await removeMember(ctx, s.user, s.workspaceId, String(req.body.email ?? ''));
    back(res, '/members', 'Removed');
  });

  // ---- OAuth consent for agents ----

  const authzId = (req: Request) => z.string().regex(/^[0-9A-Z]{16}$/).parse(req.params.id);

  router.get('/oauth/consent/:id', requireUser, recent, async (req, res) => {
    const s = session(req);
    const authz = await getAuthorization(ctx, authzId(req));
    const [folders, workspaces] = await Promise.all([listSecrets(ctx, s.workspaceId).then(foldersOf), listMemberships(ctx, s.user.id)]);
    send(res, views.consentPage(await chrome(req), authz, { folders, workspaces }));
  });

  router.post('/oauth/consent/:id', requireUser, recent, async (req, res) => {
    const id = authzId(req);
    if (req.body.decision !== 'approve') return res.redirect(303, await denyAuthorization(ctx, id));
    const target = await approveAuthorization(
      ctx,
      session(req).user,
      id,
      { workspaceId: req.body.workspaceId, folder: req.body.folder ?? '', tags: req.body.tags ?? '', names: req.body.names ?? '', label: req.body.label },
      req.ip,
    );
    res.redirect(303, target);
  });

  return router;
}
