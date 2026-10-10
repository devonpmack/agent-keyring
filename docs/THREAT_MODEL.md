# Threat model

Written before the code, then updated to match what was built. The central question is the one most secret stores
skip: **what happens when the caller is an AI agent that can be talked into anything?**

## System in one paragraph

A small web service holds named secrets. Humans sign in with Google (OIDC) and manage
secrets, policies, grants and the authenticator. AI agents (Claude Code, Cursor, scripts)
connect through OAuth 2.1 (authorization code + PKCE, dynamic client registration) and
call a REST API or a remote MCP server. Secrets live in folders; each agent grant is
limited to one folder and optionally narrowed by tag or exact path. Every secret has a
policy set only by a human: `open` (an authorized agent may fetch it) or `approval`
(each fetch needs a fresh human approval with a TOTP code or passkey). Values are envelope-encrypted: a random data key per secret,
wrapped by a master key that never leaves a cloud KMS.

## Assets (most to least valuable)

1. Secret plaintext, including TOTP seeds of third-party accounts.
2. The KMS master key (or the cloud identity that can call `decrypt` on it).
3. The vault owner's authenticator seed (it is what turns "agent asked" into "human approved").
4. Human sessions (they can change policy, create grants, enroll the authenticator).
5. Agent access and refresh tokens.
6. The audit log (integrity matters: it is how misuse is noticed).

## Attackers

| Attacker | Capability we assume |
|---|---|
| **Prompt-injected agent** (central case) | Fully controls what an authorized agent asks for and what reason it gives. Can ask repeatedly, can lie in the reason, can ask the user to paste a TOTP code into chat. |
| Leaked agent token | Has a valid access or refresh token for one grant. |
| Database thief | Has a full copy of Postgres (backup leak, SQL injection, stolen snapshot). No KMS access. |
| Network / browser attacker | Can make the human's browser send cross-site requests, phish, or observe URLs and referrers. |
| Malicious OAuth client | Registers itself via dynamic client registration and tries to look legitimate. |
| Another tenant (managed mode) | A legitimate user of the same deployment trying to reach someone else's workspace. |
| Compromised host (out of scope to fully defend) | Root on the running service or on the human's laptop. |

## Trust boundaries

1. **Agent ↔ vault.** Everything the agent sends is untrusted, including its stated
   reason. The server, not the agent or the MCP client, decides whether a secret is
   released.
2. **Human browser ↔ vault.** Trusted only after Google OIDC, with a fresh re-auth for
   admin actions, CSRF tokens plus an Origin check, and `__Host-`, `SameSite`,
   `Secure`, `HttpOnly` cookies.
3. **Vault ↔ KMS.** The only place a data key can be unwrapped. The service's cloud
   role can `encrypt`/`decrypt` with one key and nothing else.
4. **Vault ↔ Postgres.** The database is treated as storage that may leak, never as a
   place where plaintext lives.

## Scenarios and what happens

**Agent is prompt-injected.** It can request any secret inside its grant scope, so the
grant scope is the blast radius for `open` secrets and the design says so plainly.
For `approval` secrets the server returns `pending_approval` and nothing else. The
human sees, on the vault's own page, the exact secret name, the requesting client
(registered name, client ID, first-seen date), the grant, the agent's reason (labeled
as *agent-supplied, unverified*), and the request time. Approval is bound to that one
request ID and to that client, expires in 5 minutes and is consumed on first use. An
injected agent cannot widen its scope, cannot approve itself, and cannot reuse an
approval. There are no agent tools for creating secrets, editing policy or managing
grants. The remaining risk is the human approving a request they should not, so the
approval page is built to make the request legible rather than fast to click through.

**Agent asks the user to type a TOTP code into chat (path b).** Off by default,
per-secret opt-in. The code reaches the model context and any logs the client keeps.
Mitigations: the code is single-use (after a code is accepted, no code for that time
step or an earlier one is accepted again), it must be sent with the pending request ID
it approves, and only within 5 minutes of that request. It is checked against the
authenticator of the human who connected that agent. A code the server has already
accepted is rejected, so one typed code approves at most one request. The server cannot
know which request the human *meant*: the agent chooses the request ID it pairs the
code with. Residual risk, documented: an injected
agent can open a request for secret X while telling the user it is for secret Y, so path
(b) is only for secrets where that confusion is acceptable. A second residual: an injected
agent can submit wrong codes to lock that human's approvals for 15 minutes (a denial of
service, not a disclosure).

**Agent token leaks.** Access tokens live 10 minutes; refresh tokens rotate on use with
reuse detection (a replayed refresh token revokes the whole grant). A leaked token gets
`open` secrets in scope until revoked, and only `pending_approval` for `approval`
secrets. The human revokes the grant in one click; revocation is checked on every
request, not cached past the token.

**Database leaks.** The thief gets ciphertext, wrapped data keys, metadata (names,
tags, notes, policies), audit rows, hashed tokens and the owner's authenticator seed
(encrypted with the same envelope scheme). Without KMS `decrypt` none of it is usable.
Notes and names are *not* encrypted and are documented as metadata, so users are told
not to put secret material in them. Tokens are stored as SHA-256 hashes, so a DB copy
cannot mint sessions.

**KMS credentials leak together with the DB.** Game over for stored secrets; this is the
one-way door. Mitigations are operational: the service identity is the only principal
with `decrypt`, KMS audit logs are on, and key rotation plus re-wrapping is scripted.

**Human session hijack / CSRF.** Admin actions need a Google re-auth within the last
5 minutes (`max_age=0` is sent and a fresh `auth_time` is required; a token without one
is refused). Replacing an enrolled authenticator additionally needs a current code from
it, so a hijacked session cannot swap in its own and then approve requests. Flash
messages travel in a one-time cookie, never the URL, so an agent cannot add text to the
approval link it shows the human. All state-changing form posts carry a CSRF
token. Nothing secret ever goes in a URL (secret values, codes and tokens travel only
in bodies or headers), so referrers and access logs are clean.

**Malicious client via dynamic registration.** Registration only creates an inert
public client (no client secrets are issued or stored), with redirect URIs limited to
https, loopback http or private-use schemes. A human must complete the consent screen,
which needs a fresh Google re-auth and shows the client name *and* the exact redirect
URI the code will be sent to (with a warning when it is a website rather than a local
app), and chooses the scope (a folder, optionally narrowed by tags or paths). Clients
that have never been approved are labeled as new. A replayed authorization code revokes
the grant it produced.

**Online guessing of TOTP codes.** 5 consecutive wrong codes lock that approver for
15 minutes and raise an alert (audit event plus webhook notification); 5 wrong codes on
one request deny it. With 10^6 codes and those limits, guessing is not practical.

**Phishing the approval.** A look-alike page could collect a TOTP code. Passkeys close
this: the browser only signs for the vault's origin, and the challenge is derived from
the approval request ID, so a signature cannot be relayed to approve something else.

**Another tenant (managed mode).** Invites never auto-join: every new user gets their
own workspace, and joining another one is an explicit accept (members can approve each
other's requests, so membership is a trust decision). The consent page's "new client"
label only counts grants in the user's own workspaces. Every query is scoped by workspace ID, grants carry
their workspace, and every ciphertext binds `workspace_id:secret_id` as authenticated
data at both encryption layers, so even a query bug that returned another tenant's row
would not decrypt under the wrong context. Removing a member revokes the grants they
created and ends their sessions immediately.

## Non-goals for the MVP

Defending against root on the vault host or the human's laptop; multi-region HA;
requiring attested hardware keys (passkeys work, attestation is not enforced); protecting secrets *after* an agent has received them
(an agent with a value can exfiltrate it, so the policy decides whether it gets it at all).

## Logging rule

Audit and application logs record actor, client, secret name, action, reason, outcome
and timestamp. They never record secret values, TOTP codes, tokens or request bodies.
Errors returned to clients are generic and carry a request ID.
