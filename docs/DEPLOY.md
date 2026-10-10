# Deploying agent-keyring

The same container image runs self-hosted (`MODE=self_hosted`) and managed
(`MODE=managed`). This guide covers Cloud Run with Cloud SQL and Cloud KMS, then
notes for AWS. Nothing here is created for you: every command costs money once
you run it, so read it first.

## What you need

| Piece | Why |
|---|---|
| A domain with HTTPS | `BASE_URL`. Passkeys and secure cookies are bound to it. |
| Postgres 15+ | Cloud SQL, RDS, Neon, or your own. |
| A KMS key | GCP Cloud KMS or AWS KMS symmetric key. It holds the master key. |
| A Google OAuth client | "Web application", redirect URI `https://<domain>/auth/callback`. |
| A secret manager | For `GOOGLE_CLIENT_SECRET` and `DATABASE_URL`. |

## Configuration

| Variable | Example | Notes |
|---|---|---|
| `NODE_ENV` | `production` | Refuses the local KMS adapter, `pglite:` and non-https `BASE_URL`. |
| `BASE_URL` | `https://keyring.example.com` | Public URL, no trailing slash. |
| `MODE` | `self_hosted` / `managed` | |
| `OWNER_EMAIL` | `you@example.com` | Self-hosted: the first owner. |
| `DATABASE_URL` | `postgres://…` | Mount from the secret manager. |
| `GOOGLE_CLIENT_ID` | `…apps.googleusercontent.com` | Not secret. |
| `GOOGLE_CLIENT_SECRET` | | Mount from the secret manager. |
| `KMS_PROVIDER` | `gcp` / `aws` | |
| `GCP_KMS_KEY_NAME` | `projects/p/locations/l/keyRings/r/cryptoKeys/k` | |
| `AWS_KMS_KEY_ID`, `AWS_REGION` | `arn:aws:kms:…` | |
| `TRUST_PROXY` | `1` | Number of proxies in front (Cloud Run: 1). |
| `NOTIFY_WEBHOOK_URL` | `https://ntfy.sh/<random-topic>` | Optional approval notifications. Treat the URL as a secret. |

Any variable can instead be given as `NAME_FILE=/path`, which is read at startup.
This is how secret-manager volume mounts work.

## Google Cloud (Cloud Run + Cloud SQL + Cloud KMS)

```bash
PROJECT=my-project REGION=us-central1 SA=agent-keyring

# Service identity with nothing but what it needs
gcloud iam service-accounts create $SA --project $PROJECT

# Master key (HSM protection level is available if you want it).
# `date -v+90d` is macOS syntax; on Linux use `date -u -d +90days +%Y-%m-%dT%H:%M:%SZ`.
gcloud kms keyrings create agent-keyring --location $REGION --project $PROJECT
gcloud kms keys create master --keyring agent-keyring --location $REGION \
  --purpose encryption --rotation-period 90d --next-rotation-time $(date -u -v+90d +%Y-%m-%dT%H:%M:%SZ) \
  --project $PROJECT

# Least privilege: encrypt/decrypt on this one key, nothing else
gcloud kms keys add-iam-policy-binding master --keyring agent-keyring --location $REGION \
  --member serviceAccount:$SA@$PROJECT.iam.gserviceaccount.com \
  --role roles/cloudkms.cryptoKeyEncrypterDecrypter --project $PROJECT

# Secrets for the service itself
printf %s "$GOOGLE_CLIENT_SECRET" | gcloud secrets create google-client-secret --data-file=- --project $PROJECT
printf %s "$DATABASE_URL" | gcloud secrets create database-url --data-file=- --project $PROJECT
for s in google-client-secret database-url; do
  gcloud secrets add-iam-policy-binding $s --role roles/secretmanager.secretAccessor \
    --member serviceAccount:$SA@$PROJECT.iam.gserviceaccount.com --project $PROJECT
done

# Cloud SQL: grant roles/cloudsql.client to the service account, and use the
# connector socket in DATABASE_URL (host=/cloudsql/<instance>).

gcloud run deploy agent-keyring --source . --region $REGION --project $PROJECT \
  --service-account $SA@$PROJECT.iam.gserviceaccount.com \
  --set-env-vars NODE_ENV=production,BASE_URL=https://keyring.example.com,MODE=self_hosted,OWNER_EMAIL=you@example.com,KMS_PROVIDER=gcp,GCP_KMS_KEY_NAME=projects/$PROJECT/locations/$REGION/keyRings/agent-keyring/cryptoKeys/master,GOOGLE_CLIENT_ID=$GOOGLE_CLIENT_ID,TRUST_PROXY=1 \
  --set-secrets GOOGLE_CLIENT_SECRET=google-client-secret:latest,DATABASE_URL=database-url:latest \
  --add-cloudsql-instances $PROJECT:$REGION:<instance> \
  --min-instances 0 --max-instances 3
```

Migrations run automatically at startup.

Turn on Cloud KMS Data Access audit logs so every `Decrypt` on the master key is
recorded outside the app.

## AWS (ECS/Fargate or App Runner + RDS + KMS)

- Create a symmetric KMS key. The task role gets `kms:Encrypt` and `kms:Decrypt`
  on that key ARN only, with a condition on `kms:EncryptionContextKeys` = `purpose`.
- Put `GOOGLE_CLIENT_SECRET` and `DATABASE_URL` in Secrets Manager and inject them
  as task secrets.
- Set `KMS_PROVIDER=aws`, `AWS_KMS_KEY_ID=<arn>` and `AWS_REGION`.
- CloudTrail records every `Decrypt` with its encryption context, which includes
  the workspace and secret ID (never the value).

## Key rotation

Every stored value is `AES-256-GCM(data key, value)`, and the data key is wrapped
by the KMS master key. The wrapped key records which master key wrapped it.

**Routine rotation (same key, new version).** Turn on automatic rotation in
Cloud KMS, or AWS KMS annual rotation. New data keys are wrapped with the new
version. Old ciphertexts keep decrypting because the provider tracks the version
inside the ciphertext. No downtime, and no app change.

**Re-wrapping existing data keys** (after a rotation you want to fully apply, or
before disabling an old version):

```bash
NODE_ENV=production … npm run rewrap
```

This unwraps and re-wraps every data key, including users' authenticator seeds.
Secret values are never decrypted, and it is safe to re-run.

**Moving to a different master key** (new key ring, new account, GCP to AWS):

1. Give the service decrypt on the old key and encrypt/decrypt on the new one.
2. Deploy with the new `KMS_*` settings. Rows record their own key ID, so the
   adapter keeps unwrapping old rows with the old key (same provider only).
3. Run `npm run rewrap` and check that the reported count matches your secrets.
4. Remove the service's access to the old key, then schedule it for destruction.

Moving between providers (GCP to AWS) needs both adapters during step 2. Run the
rewrap with a small script that unwraps through the old adapter and wraps
through the new one; `rewrap()` in `src/crypto/envelope.ts` takes any `Kms`.

**If the database leaks:** nothing to rotate for secret values (they are
useless without KMS), but treat secret names, tags and notes as disclosed.
**If KMS access and the database leak together:** rotate every stored secret at
its source. The vault cannot help you there.

## Managed mode

Same deployment with `MODE=managed` and no `OWNER_EMAIL`. Anyone with a Google
account can sign in and gets a workspace. Before offering it to others:

- Put the Google OAuth consent screen through verification.
- Run more than one instance. Rate limits are already shared through Postgres.
- Consider per-workspace KMS keys (see the README's next steps).
