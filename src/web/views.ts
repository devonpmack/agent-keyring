import type { ApprovalView } from '../domain/approvals.js';
import type { AuditRow } from '../domain/audit.js';
import type { GrantListing } from '../domain/grants.js';
import { describeScope, joinPath } from '../domain/paths.js';
import type { Passkey } from '../domain/passkeys.js';
import type { SecretMeta } from '../domain/secrets.js';
import type { Invite, Member, Membership } from '../domain/users.js';
import type { PendingAuthorization } from '../oauth/consent.js';
import { html, type Html } from './html.js';
import type { Session } from './session.js';

type Nav = 'secrets' | 'approvals' | 'agents' | 'audit' | 'settings' | 'members' | 'none';

export type PageChrome = { session?: Session; memberships?: Membership[]; pendingCount?: number; flash?: string; error?: string; nav?: Nav };

function fmt(d: Date | null | undefined): string {
  if (!d) return '—';
  return d.toISOString().replace('T', ' ').slice(0, 19) + 'Z';
}

function csrf(session: Session): Html {
  return html`<input type="hidden" name="_csrf" value="${session.csrfToken}">`;
}

export function layout(title: string, chrome: PageChrome, body: Html): string {
  const s = chrome.session;
  const link = (key: Nav, href: string, label: string, extra?: Html | string) =>
    html`<a href="${href}" class="${chrome.nav === key ? 'active' : ''}">${label}${extra}</a>`;
  const badge = chrome.pendingCount ? html` <span class="badge">${chrome.pendingCount}</span>` : '';
  const others = (chrome.memberships ?? []).filter(m => m.workspace_id !== s?.workspaceId);
  return html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="same-origin">
<title>${title} · agent-keyring</title>
<link rel="stylesheet" href="/static/app.css">
</head>
<body>
<header class="top">
  <a class="brand" href="/">agent-keyring</a>
  ${s
    ? html`<nav>
        ${link('secrets', '/', 'Secrets')}
        ${link('approvals', '/approvals', 'Approvals', badge)}
        ${link('agents', '/agents', 'Agents')}
        ${link('audit', '/audit', 'Audit log')}
        ${link('settings', '/settings', 'Settings')}
        ${s.role === 'owner' ? link('members', '/members', 'Members') : ''}
      </nav>
      <div class="who">
        ${others.length
          ? html`<form method="post" action="/workspace" class="inline">${csrf(s)}
              <select name="workspaceId" aria-label="Switch workspace" class="js-autosubmit">
                <option selected>${chrome.memberships?.find(m => m.workspace_id === s.workspaceId)?.workspace_name}</option>
                ${others.map(m => html`<option value="${m.workspace_id}">${m.workspace_name}</option>`)}
              </select><noscript><button>Switch</button></noscript></form>`
          : ''}
        <span>${s.user.email}</span>
        <form method="post" action="/logout" class="inline">${csrf(s)}<button class="link">Sign out</button></form>
      </div>`
    : ''}
</header>
<main>
${chrome.flash ? html`<p class="flash">${chrome.flash}</p>` : ''}
${chrome.error ? html`<p class="flash error">${chrome.error}</p>` : ''}
${body}
</main>
<script src="/static/vendor/webauthn.js"></script>
<script src="/static/app.js" type="module"></script>
</body>
</html>`.toString();
}

export function loginPage(returnTo: string, error?: string): string {
  return layout('Sign in', { error }, html`
<section class="narrow center">
  <h1>agent-keyring</h1>
  <p class="muted">Secrets for AI agents, with a human in the loop where it matters.</p>
  <a class="button primary" href="/auth/google?return_to=${encodeURIComponent(returnTo)}">Sign in with Google</a>
</section>`);
}

export function errorPage(chrome: PageChrome, status: number, message: string, reauth?: string): string {
  return layout('Error', chrome, html`
<section class="narrow">
  <h1>${status === 404 ? 'Not found' : 'Something stopped this'}</h1>
  <p>${message}</p>
  ${reauth ? html`<p><a class="button primary" href="/auth/google?purpose=reauth&amp;return_to=${encodeURIComponent(reauth)}">Re-authenticate with Google</a></p>` : ''}
  <p><a href="/">Back to secrets</a></p>
</section>`);
}

function policyBadge(s: Pick<SecretMeta, 'policy' | 'allow_chat_approval'>): Html {
  if (s.policy === 'open') return html`<span class="pill open">open</span>`;
  return html`<span class="pill approval">approval${s.allow_chat_approval ? ' · chat code ok' : ''}</span>`;
}

export function secretsPage(chrome: PageChrome, secrets: SecretMeta[], folders: string[], current: string | undefined): string {
  const shown = current === undefined ? secrets : secrets.filter(s => s.folder === current || s.folder.startsWith(current + '/'));
  return layout('Secrets', { ...chrome, nav: 'secrets' }, html`
<div class="split">
  <aside class="folders">
    <h2>Folders</h2>
    <ul>
      <li><a href="/" class="${current === undefined ? 'active' : ''}">All secrets</a></li>
      ${folders.map(f => html`<li class="depth-${Math.min(f.split('/').length - 1, 7)}"><a href="/?folder=${encodeURIComponent(f)}" class="${current === f ? 'active' : ''}">${f.split('/').pop()}/</a></li>`)}
    </ul>
  </aside>
  <section>
    <div class="row">
      <h1>${current === undefined ? 'All secrets' : current + '/'}</h1>
      <a class="button primary" href="/secrets/new${current ? `?folder=${encodeURIComponent(current)}` : ''}">New secret</a>
    </div>
    ${shown.length === 0
      ? html`<p class="empty">No secrets here yet. Values are encrypted with a per-secret key wrapped by your KMS key.</p>`
      : html`<div class="table-wrap"><table>
          <thead><tr><th>Path</th><th>Kind</th><th>Policy</th><th>Tags</th><th>Updated</th></tr></thead>
          <tbody>
          ${shown.map(s => html`<tr>
            <td><a href="/secrets/${s.id}"><code>${joinPath(s.folder, s.name)}</code></a></td>
            <td>${s.kind === 'totp_seed' ? 'TOTP seed' : 'static'}</td>
            <td>${policyBadge(s)}</td>
            <td>${s.tags.map(t => html`<span class="tag">${t}</span>`)}</td>
            <td class="muted">${fmt(s.updated_at)}</td>
          </tr>`)}
          </tbody>
        </table></div>`}
  </section>
</div>`);
}

function policyFields(s: Partial<SecretMeta>): Html {
  return html`
  <fieldset>
    <legend>Agent access policy</legend>
    <label class="choice"><input type="radio" name="policy" value="open" ${s.policy === 'open' ? 'checked' : ''} required>
      <span><strong>Open</strong> — an authorized agent can fetch it whenever it asks.</span></label>
    <label class="choice"><input type="radio" name="policy" value="approval" ${s.policy !== 'open' ? 'checked' : ''}>
      <span><strong>Approval</strong> — every fetch waits for a human to approve with an authenticator code or passkey.</span></label>
    <label class="choice indent"><input type="checkbox" name="allowChatApproval" value="1" ${s.allow_chat_approval ? 'checked' : ''}>
      <span>Also accept a code typed into the agent chat. <span class="warn">The code passes through the model's context; only enable this when an agent mislabeling the request would not hurt you.</span></span></label>
  </fieldset>`;
}

export function newSecretPage(chrome: PageChrome, folder: string, folders: string[]): string {
  const s = chrome.session!;
  return layout('New secret', { ...chrome, nav: 'secrets' }, html`
<section class="narrow">
  <h1>New secret</h1>
  <form method="post" action="/secrets" class="stack" autocomplete="off">
    ${csrf(s)}
    <div class="two">
      <label>Folder <input name="folder" value="${folder}" list="folders" placeholder="prod/stripe" pattern="[A-Za-z0-9/_.\\-]*"></label>
      <label>Name <input name="name" required placeholder="API_KEY" pattern="[A-Za-z0-9][A-Za-z0-9_.\\-]*" maxlength="64"></label>
    </div>
    <datalist id="folders">${folders.map(f => html`<option value="${f}">`)}</datalist>
    <fieldset>
      <legend>Kind</legend>
      <label class="choice"><input type="radio" name="kind" value="static" checked> <span><strong>Static</strong> — an opaque string such as an API key.</span></label>
      <label class="choice"><input type="radio" name="kind" value="totp_seed"> <span><strong>TOTP seed</strong> — a third-party MFA seed (base32 or otpauth:// URI). Agents only ever get the current 6-digit code.</span></label>
    </fieldset>
    <label>Value <textarea name="value" required rows="3" spellcheck="false" class="mono"></textarea></label>
    <label>Notes <span class="muted">(stored unencrypted as metadata — never put secret material here)</span><textarea name="notes" rows="2" maxlength="2000"></textarea></label>
    <label>Tags <input name="tags" placeholder="billing, prod"></label>
    ${policyFields({ policy: 'approval' })}
    <button class="primary">Save secret</button>
  </form>
</section>`);
}

export function secretPage(chrome: PageChrome, secret: SecretMeta, recent: AuditRow[]): string {
  const s = chrome.session!;
  const path = joinPath(secret.folder, secret.name);
  return layout(path, { ...chrome, nav: 'secrets' }, html`
<section class="narrow">
  <p class="muted"><a href="/?folder=${encodeURIComponent(secret.folder)}">${secret.folder || 'root'}/</a></p>
  <h1><code>${path}</code></h1>
  <p>${secret.kind === 'totp_seed' ? 'TOTP seed' : 'Static secret'} · version ${secret.version} · ${policyBadge(secret)}</p>
  <form method="post" action="/secrets/${secret.id}" class="stack" autocomplete="off">
    ${csrf(s)}
    <label>Replace value <span class="muted">(leave empty to keep the current value; values are never shown)</span>
      <textarea name="value" rows="2" spellcheck="false" class="mono"></textarea></label>
    <label>Notes <textarea name="notes" rows="2" maxlength="2000">${secret.notes}</textarea></label>
    <label>Tags <input name="tags" value="${secret.tags.join(', ')}"></label>
    ${policyFields(secret)}
    <button class="primary">Save changes</button>
  </form>
  <form method="post" action="/secrets/${secret.id}/delete" class="danger-zone">
    ${csrf(s)}
    <button class="danger js-confirm" data-confirm="Delete ${path}? Agents lose access immediately.">Delete secret</button>
  </form>
  <h2>Recent activity</h2>
  ${auditTable(recent)}
</section>`);
}

export function approvalsPage(chrome: PageChrome, approvals: ApprovalView[]): string {
  const pending = approvals.filter(a => a.effective_status === 'pending');
  const rest = approvals.filter(a => a.effective_status !== 'pending');
  const rows = (list: ApprovalView[]) => html`<div class="table-wrap"><table>
    <thead><tr><th>Request</th><th>Secret</th><th>Agent</th><th>Reason</th><th>Status</th><th>When</th></tr></thead>
    <tbody>${list.map(a => html`<tr>
      <td><a href="/approvals/${a.id}"><code>${a.id}</code></a></td>
      <td><code>${a.secret_path}</code></td>
      <td>${a.client_name}</td>
      <td class="reason">${a.reason}</td>
      <td><span class="pill ${a.effective_status}">${a.effective_status}</span></td>
      <td class="muted">${fmt(a.created_at)}</td>
    </tr>`)}</tbody></table></div>`;
  return layout('Approvals', { ...chrome, nav: 'approvals' }, html`
<h1>Approvals</h1>
<h2>Waiting for you</h2>
${pending.length ? rows(pending) : html`<p class="empty">Nothing is waiting. Requests expire after 5 minutes.</p>`}
<h2>Recent</h2>
${rest.length ? rows(rest) : html`<p class="empty">No past requests.</p>`}`);
}

export function approvalPage(chrome: PageChrome, a: ApprovalView, opts: { hasAuthenticator: boolean; hasPasskey: boolean }): string {
  const s = chrome.session!;
  const pending = a.effective_status === 'pending';
  return layout(`Approve ${a.id}`, { ...chrome, nav: 'approvals' }, html`
<section class="narrow approval">
  <p class="muted">Approval request</p>
  <h1 class="request-id">${a.id}</h1>
  <p>Check that this matches the request ID your agent showed you.</p>
  <dl>
    <dt>Secret</dt><dd><code class="big">${a.secret_path}</code> ${a.secret_kind === 'totp_seed' ? html`<span class="muted">(agent receives a one-time code, never the seed)</span>` : ''}</dd>
    <dt>Requested by</dt><dd><strong>${a.client_name}</strong> <span class="muted">client ${a.client_id.slice(0, 8)} · first seen ${fmt(a.client_first_seen)} · connected by ${a.grant_owner_email}</span></dd>
    <dt>Agent's reason</dt><dd><blockquote class="reason">${a.reason}</blockquote><span class="muted">Written by the agent. It is not verified and may be wrong or manipulated.</span></dd>
    <dt>Requested</dt><dd>${fmt(a.created_at)} · expires ${fmt(a.expires_at)}</dd>
    <dt>Status</dt><dd><span class="pill ${a.effective_status}">${a.effective_status}</span>${a.decided_by_email ? html` by ${a.decided_by_email} (${a.decision_method})` : ''}</dd>
  </dl>
  ${pending
    ? html`
      ${opts.hasAuthenticator
        ? html`<form method="post" action="/approvals/${a.id}/approve" class="stack approve-form" autocomplete="off">
            ${csrf(s)}
            <label>Authenticator code <input name="code" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" required autofocus class="code"></label>
            <button class="primary">Approve this one fetch</button>
          </form>`
        : html`<p class="flash error">Enroll an authenticator in <a href="/settings">Settings</a> before you can approve with a code.</p>`}
      ${opts.hasPasskey
        ? html`<button class="js-passkey-approve" data-approval="${a.id}" data-csrf="${s.csrfToken}">Approve with passkey</button>`
        : ''}
      <form method="post" action="/approvals/${a.id}/deny" class="inline">${csrf(s)}<button class="danger">Deny</button></form>
      <p class="muted">Approval releases the secret once, to this agent only, within 5 minutes.</p>`
    : ''}
</section>`);
}

export function agentsPage(chrome: PageChrome, grants: GrantListing[], mcpUrl: string): string {
  const s = chrome.session!;
  return layout('Agents', { ...chrome, nav: 'agents' }, html`
<h1>Connected agents</h1>
<p>Connect Claude Code: <code class="copy">claude mcp add --transport http agent-keyring ${mcpUrl}</code></p>
${grants.length === 0
  ? html`<p class="empty">No agents connected yet.</p>`
  : html`<div class="table-wrap"><table>
    <thead><tr><th>Agent</th><th>Access</th><th>Connected by</th><th>Created</th><th>Last used</th><th></th></tr></thead>
    <tbody>${grants.map(g => html`<tr class="${g.revoked_at ? 'revoked' : ''}">
      <td><strong>${g.label}</strong><br><span class="muted">${g.client_name} · ${g.redirect_host}</span></td>
      <td>${describeScope({ folder: g.scope_folder, tags: g.scope_tags, names: g.scope_names })}</td>
      <td>${g.user_email}</td>
      <td class="muted">${fmt(g.created_at)}</td>
      <td class="muted">${fmt(g.last_used_at)}</td>
      <td>${g.revoked_at
        ? html`<span class="muted">revoked ${fmt(g.revoked_at)}</span>`
        : html`<form method="post" action="/agents/${g.id}/revoke">${csrf(s)}<button class="danger js-confirm" data-confirm="Revoke ${g.label}? It loses access immediately.">Revoke</button></form>`}</td>
    </tr>`)}</tbody></table></div>`}`);
}

export function auditTable(rows: AuditRow[]): Html {
  if (rows.length === 0) return html`<p class="empty">No events.</p>`;
  return html`<div class="table-wrap"><table class="audit">
    <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Outcome</th><th>Secret</th><th>Reason</th></tr></thead>
    <tbody>${rows.map(r => html`<tr>
      <td class="muted">${fmt(r.at)}</td>
      <td>${r.actor_label} <span class="muted">${r.actor_type}</span></td>
      <td><code>${r.action}</code>${r.approval_id ? html` <a href="/approvals/${r.approval_id}" class="muted">${r.approval_id}</a>` : ''}</td>
      <td><span class="pill ${r.outcome}">${r.outcome}</span></td>
      <td>${r.secret_path ? html`<code>${r.secret_path}</code>` : ''}</td>
      <td class="reason">${r.reason ?? ''}</td>
    </tr>`)}</tbody></table></div>`;
}

export function auditPage(chrome: PageChrome, rows: AuditRow[], filter: { action?: string; secret?: string }): string {
  const last = rows.at(-1);
  const params = new URLSearchParams();
  if (filter.action) params.set('action', filter.action);
  if (filter.secret) params.set('secret', filter.secret);
  if (last) params.set('before', last.at.toISOString());
  return layout('Audit log', { ...chrome, nav: 'audit' }, html`
<h1>Audit log</h1>
<form method="get" class="filters">
  <select name="action">
    <option value="">All actions</option>
    ${['secret.fetch', 'secret.list', 'approval', 'grant', 'secret.policy_change', 'secret', 'authenticator', 'auth', 'member'].map(
      a => html`<option value="${a}" ${filter.action === a ? 'selected' : ''}>${a}</option>`,
    )}
  </select>
  <input name="secret" value="${filter.secret ?? ''}" placeholder="exact secret path">
  <button>Filter</button>
</form>
${auditTable(rows)}
${rows.length >= 100 ? html`<p><a href="/audit?${params.toString()}">Older →</a></p>` : ''}
<p class="muted">Values, authenticator codes and tokens are never logged.</p>`);
}

export function settingsPage(chrome: PageChrome, opts: { enrolledAt: Date | null; enrollment?: { qr: string; secret: string }; passkeys: Passkey[]; invites: Invite[] }): string {
  const s = chrome.session!;
  return layout('Settings', { ...chrome, nav: 'settings' }, html`
<section class="narrow">
  <h1>Settings</h1>
  ${opts.invites.length
    ? html`<h2>Invitations</h2>
      <p class="muted">Members of a workspace can approve each other's requests. Only join workspaces you trust.</p>
      <ul class="plain">${opts.invites.map(i => html`<li><strong>${i.workspace_name}</strong> <span class="muted">invited ${fmt(i.created_at)}</span>
        <form method="post" action="/invites/${i.workspace_id}/accept" class="inline">${csrf(s)}<button class="link">Accept</button></form> ·
        <form method="post" action="/invites/${i.workspace_id}/decline" class="inline">${csrf(s)}<button class="link danger">Decline</button></form></li>`)}</ul>`
    : ''}
  <h2>Authenticator app</h2>
  ${opts.enrollment
    ? html`<p>Scan this with Google Authenticator (or any TOTP app), then enter the code it shows.</p>
      <img class="qr" src="${opts.enrollment.qr}" alt="Authenticator QR code" width="200" height="200">
      <p class="muted">Can't scan? Enter this key: <code>${opts.enrollment.secret}</code></p>
      <form method="post" action="/settings/authenticator/confirm" class="stack" autocomplete="off">
        ${csrf(s)}
        <label>Code <input name="code" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" required class="code"></label>
        <button class="primary">Confirm</button>
      </form>`
    : opts.enrolledAt
      ? html`<p>Enrolled ${fmt(opts.enrolledAt)}. To replace it, enter a current code from the old one.</p>
        <form method="post" action="/settings/authenticator" class="row-left" autocomplete="off">${csrf(s)}
          <input name="current_code" inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" required placeholder="Current code" class="code">
          <button>Replace authenticator</button></form>`
      : html`<p>Not enrolled. You need an authenticator to approve requests.</p>
        <form method="post" action="/settings/authenticator">${csrf(s)}<button class="primary">Set up authenticator</button></form>`}

  <h2>Passkeys</h2>
  <p class="muted">Approve requests with Touch ID, Windows Hello or a security key. Passkeys only work on this site, so they can't be phished.</p>
  ${opts.passkeys.length
    ? html`<ul class="plain">${opts.passkeys.map(p => html`<li>${p.name} <span class="muted">added ${fmt(p.created_at)} · last used ${fmt(p.last_used_at)}</span>
        <form method="post" action="/settings/passkeys/${encodeURIComponent(p.id)}/delete" class="inline">${csrf(s)}<button class="link danger">Remove</button></form></li>`)}</ul>`
    : ''}
  <div class="row-left">
    <input id="passkey-name" placeholder="Name, e.g. MacBook Touch ID" maxlength="60">
    <button class="js-passkey-register" data-csrf="${s.csrfToken}">Add passkey</button>
  </div>
</section>`);
}

export function membersPage(chrome: PageChrome, members: Member[], mode: 'self_hosted' | 'managed'): string {
  const s = chrome.session!;
  return layout('Members', { ...chrome, nav: 'members' }, html`
<section class="narrow">
  <h1>Members</h1>
  <p class="muted">${mode === 'self_hosted' ? 'Only these Google accounts can sign in.' : 'These Google accounts can use this workspace.'} Members can manage secrets, connect agents and approve requests.</p>
  <div class="table-wrap"><table>
    <thead><tr><th>Email</th><th>Role</th><th>Status</th><th></th></tr></thead>
    <tbody>${members.map(m => html`<tr>
      <td>${m.email}</td><td>${m.role}</td><td>${m.user_id ? 'active' : 'invited'}</td>
      <td>${m.role === 'owner' ? '' : html`<form method="post" action="/members/remove">${csrf(s)}<input type="hidden" name="email" value="${m.email}"><button class="link danger js-confirm" data-confirm="Remove ${m.email}? Agents they connected are revoked.">Remove</button></form>`}</td>
    </tr>`)}</tbody>
  </table></div>
  <form method="post" action="/members" class="row-left">
    ${csrf(s)}
    <input name="email" type="email" placeholder="teammate@example.com" required>
    <button class="primary">Add to allowlist</button>
  </form>
</section>`);
}

export function consentPage(chrome: PageChrome, authz: PendingAuthorization, opts: { folders: string[]; workspaces: Membership[] }): string {
  const s = chrome.session!;
  return layout('Connect an agent', { ...chrome, nav: 'none' }, html`
<section class="narrow consent">
  <h1>Connect <em>${authz.client_name}</em>?</h1>
  <dl>
    <dt>Client</dt><dd>${authz.client_name} <span class="muted">${authz.client_id}</span>${authz.previously_granted ? '' : html` <span class="pill pending">new client</span>`}</dd>
    <dt>Sends access to</dt><dd><code>${authz.redirect_uri}</code>
      ${authz.redirect_kind === 'web'
        ? html`<p class="flash error">This is a website, not an app on your computer. Anyone who controls it gets this access. Only continue if you recognize it.</p>`
        : html`<span class="muted">${authz.redirect_kind === 'loopback' ? '(an app on this computer)' : '(a desktop app)'}</span>`}</dd>
    <dt>Registered</dt><dd>${fmt(authz.client_first_seen)}</dd>
  </dl>
  <p>The agent will be able to list secret names in the scope you choose and fetch <strong>open</strong> secrets on its own. <strong>Approval</strong> secrets still need you every time.</p>
  <form method="post" action="/oauth/consent/${authz.id}" class="stack">
    ${csrf(s)}
    ${opts.workspaces.length > 1
      ? html`<label>Workspace <select name="workspaceId">${opts.workspaces.map(w => html`<option value="${w.workspace_id}" ${w.workspace_id === s.workspaceId ? 'selected' : ''}>${w.workspace_name}</option>`)}</select></label>`
      : html`<input type="hidden" name="workspaceId" value="${s.workspaceId}">`}
    <label>Folder this agent can see
      <select name="folder" required>
        <option value="" disabled selected>Choose a folder…</option>
        ${opts.folders.map(f => html`<option value="${f}">${f}/ (and subfolders)</option>`)}
        <option value="">Everything (all folders)</option>
      </select>
    </label>
    <details>
      <summary>Narrow further</summary>
      <label>Only secrets with one of these tags <input name="tags" placeholder="ci, staging"></label>
      <label>Only these exact paths <input name="names" placeholder="prod/stripe/API_KEY, prod/github/TOKEN"></label>
    </details>
    <label>Label <input name="label" maxlength="80" placeholder="${authz.client_name} on my laptop"></label>
    <div class="row-left">
      <button class="primary" name="decision" value="approve">Allow access</button>
      <button name="decision" value="deny" formnovalidate>Deny</button>
    </div>
  </form>
</section>`);
}
