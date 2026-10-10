// Re-wraps every data key under the current KMS key (KMS_* env), e.g. after
// moving to a new master key. Secret values are never decrypted: only the
// 32-byte data keys pass through memory. Safe to re-run.
import { loadConfig } from '../config.js';
import { contexts, rewrap, type Sealed } from '../crypto/envelope.js';
import { createKms } from '../crypto/kms/index.js';
import { createDb } from '../db/index.js';

const config = loadConfig();
const kms = createKms(config.kms);
const db = createDb(config.databaseUrl);
let count = 0;

const secrets = await db.query<{ id: string; workspace_id: string; value_sealed: Sealed }>('select id, workspace_id, value_sealed from secrets');
for (const s of secrets) {
  const next = await rewrap(kms, s.value_sealed, contexts.secret(s.workspace_id, s.id));
  await db.query('update secrets set value_sealed = $2 where id = $1', [s.id, JSON.stringify(next)]);
  count++;
}

const users = await db.query<{ id: string; totp_sealed: Sealed | null; totp_pending_sealed: Sealed | null }>('select id, totp_sealed, totp_pending_sealed from users');
for (const u of users) {
  const ctxString = contexts.userTotp(u.id);
  const totp = u.totp_sealed ? await rewrap(kms, u.totp_sealed, ctxString) : null;
  const pending = u.totp_pending_sealed ? await rewrap(kms, u.totp_pending_sealed, ctxString) : null;
  await db.query('update users set totp_sealed = $2, totp_pending_sealed = $3 where id = $1', [u.id, totp && JSON.stringify(totp), pending && JSON.stringify(pending)]);
  if (totp) count++;
}

await db.close();
console.log(JSON.stringify({ msg: 'rewrap complete', keyId: kms.keyId, rewrapped: count }));
