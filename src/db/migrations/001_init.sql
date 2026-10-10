-- Sealed values are JSON envelopes (see src/crypto/envelope.ts): ciphertext plus a
-- data key wrapped by the KMS master key. Nothing in this schema holds plaintext
-- secret material or a raw credential; tokens and codes are stored as SHA-256 hashes.

create table workspaces (
  id uuid primary key,
  name text not null,
  created_at timestamptz not null
);

create table users (
  id uuid primary key,
  google_sub text not null unique,
  email text not null,
  name text not null default '',
  created_at timestamptz not null,
  totp_sealed jsonb,
  totp_pending_sealed jsonb,
  totp_enrolled_at timestamptz,
  totp_last_step integer,
  totp_failed_count integer not null default 0,
  totp_locked_until timestamptz
);

-- The email allowlist. A row with user_id null is an invite not yet accepted.
create table memberships (
  workspace_id uuid not null references workspaces(id) on delete cascade,
  email text not null,
  user_id uuid references users(id) on delete cascade,
  role text not null check (role in ('owner', 'admin')),
  created_at timestamptz not null,
  primary key (workspace_id, email)
);
create index memberships_user on memberships(user_id);

create table secrets (
  id uuid primary key,
  workspace_id uuid not null references workspaces(id) on delete cascade,
  folder text not null,
  name text not null,
  kind text not null check (kind in ('static', 'totp_seed')),
  policy text not null check (policy in ('open', 'approval')),
  allow_chat_approval boolean not null default false,
  notes text not null default '',
  tags text[] not null default '{}',
  value_sealed jsonb not null,
  version integer not null default 1,
  created_by uuid references users(id) on delete set null,
  created_at timestamptz not null,
  updated_at timestamptz not null,
  unique (workspace_id, folder, name)
);

create table oauth_clients (
  client_id text primary key,
  metadata jsonb not null,
  created_at timestamptz not null
);

-- An /authorize request waiting for a human to sign in and consent.
create table oauth_authorizations (
  id text primary key,
  client_id text not null references oauth_clients(client_id) on delete cascade,
  redirect_uri text not null,
  code_challenge text not null,
  state text,
  resource text not null,
  created_at timestamptz not null,
  expires_at timestamptz not null
);

-- A grant is one human's consent for one client, limited to a folder and
-- optionally narrowed further to tags and names (all conditions must match).
create table grants (
  id uuid primary key,
  workspace_id uuid not null references workspaces(id) on delete cascade,
  client_id text not null references oauth_clients(client_id) on delete cascade,
  user_id uuid not null references users(id) on delete cascade,
  label text not null,
  scope_folder text not null,
  scope_tags text[] not null default '{}',
  scope_names text[] not null default '{}',
  created_at timestamptz not null,
  last_used_at timestamptz,
  revoked_at timestamptz,
  revoked_by uuid references users(id) on delete set null
);
create index grants_workspace on grants(workspace_id);

create table oauth_codes (
  code_hash text primary key,
  grant_id uuid not null references grants(id) on delete cascade,
  client_id text not null,
  redirect_uri text not null,
  code_challenge text not null,
  resource text not null,
  expires_at timestamptz not null,
  used_at timestamptz
);

create table oauth_tokens (
  token_hash text primary key,
  kind text not null check (kind in ('access', 'refresh')),
  grant_id uuid not null references grants(id) on delete cascade,
  client_id text not null,
  resource text not null,
  created_at timestamptz not null,
  expires_at timestamptz not null,
  used_at timestamptz,
  revoked_at timestamptz
);
create index oauth_tokens_grant on oauth_tokens(grant_id);

create table approval_requests (
  id text primary key,
  workspace_id uuid not null references workspaces(id) on delete cascade,
  secret_id uuid not null references secrets(id) on delete cascade,
  grant_id uuid not null references grants(id) on delete cascade,
  reason text not null,
  status text not null check (status in ('pending', 'approved', 'denied', 'consumed')),
  created_at timestamptz not null,
  expires_at timestamptz not null,
  decided_at timestamptz,
  decided_by uuid references users(id) on delete set null,
  decision_method text,
  consumed_at timestamptz,
  failed_attempts integer not null default 0
);
create index approval_requests_workspace on approval_requests(workspace_id, created_at desc);

create table passkeys (
  id text primary key,
  user_id uuid not null references users(id) on delete cascade,
  public_key text not null,
  counter integer not null,
  transports text[] not null default '{}',
  name text not null,
  created_at timestamptz not null,
  last_used_at timestamptz
);

create table sessions (
  id_hash text primary key,
  user_id uuid not null references users(id) on delete cascade,
  workspace_id uuid references workspaces(id) on delete set null,
  csrf_token text not null,
  created_at timestamptz not null,
  expires_at timestamptz not null,
  auth_at timestamptz not null,
  webauthn_challenge jsonb
);

-- Browser-bound state for a Google sign-in round trip.
create table login_states (
  id_hash text primary key,
  state text not null,
  nonce text not null,
  code_verifier text not null,
  purpose text not null check (purpose in ('login', 'reauth')),
  return_to text not null,
  expires_at timestamptz not null
);

create table rate_limits (
  key text not null,
  window_start timestamptz not null,
  count integer not null,
  primary key (key, window_start)
);

create table audit_events (
  id uuid primary key,
  at timestamptz not null,
  workspace_id uuid references workspaces(id) on delete cascade,
  actor_type text not null check (actor_type in ('user', 'client', 'system')),
  actor_id text,
  actor_label text not null,
  action text not null,
  outcome text not null,
  secret_path text,
  grant_id uuid,
  approval_id text,
  reason text,
  ip text,
  detail jsonb not null default '{}'
);
create index audit_events_workspace on audit_events(workspace_id, at desc);
