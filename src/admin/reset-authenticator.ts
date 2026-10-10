// Operator recovery for a lost phone: clears a user's authenticator so they can
// enroll a new one after signing in. Run with production config and access to
// the database; the action is recorded in the audit log.
//   npm run reset-authenticator -- user@example.com
import { loadConfig } from '../config.js';
import { createDb } from '../db/index.js';

const email = process.argv[2]?.toLowerCase();
if (!email) throw new Error('Usage: npm run reset-authenticator -- user@example.com');
const db = createDb(loadConfig().databaseUrl);
const [user] = await db.query<{ id: string }>(
  `update users set totp_sealed = null, totp_pending_sealed = null, totp_enrolled_at = null, totp_last_step = null,
     totp_failed_count = 0, totp_locked_until = null where email = $1 returning id`,
  [email],
);
if (!user) throw new Error(`No user ${email}`);
await db.query(
  `insert into audit_events (id, at, workspace_id, actor_type, actor_label, action, outcome, detail)
   select gen_random_uuid(), $1, workspace_id, 'system', 'operator', 'authenticator.reset', 'success', $2 from memberships where user_id = $3`,
  [new Date(), JSON.stringify({ user: email }), user.id],
);
await db.close();
console.log(`Authenticator cleared for ${email}. They can enroll a new one in Settings.`);
