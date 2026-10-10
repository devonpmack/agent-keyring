import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { createKms } from './crypto/kms/index.js';
import { createDb } from './db/index.js';
import { migrate } from './db/migrate.js';
import { cleanupExpired } from './domain/cleanup.js';
import { systemClock, type AppContext } from './domain/context.js';
import { WebhookNotifier } from './domain/notifier.js';
import { ensureSelfHostedWorkspace } from './domain/users.js';

const config = loadConfig();
const db = createDb(config.databaseUrl);
await migrate(db);
const ctx: AppContext = { config, db, kms: createKms(config.kms), clock: systemClock, notifier: new WebhookNotifier(config.notifyWebhookUrl) };
await ensureSelfHostedWorkspace(ctx);

const server = createApp(ctx).listen(config.port, () => {
  console.log(JSON.stringify({ level: 'info', msg: 'agent-keyring listening', port: config.port, baseUrl: config.baseUrl, mode: config.mode, kms: config.kms.provider }));
});

const timer = setInterval(() => {
  cleanupExpired(ctx).catch(err => console.error(JSON.stringify({ level: 'warn', msg: 'cleanup failed', error: String(err) })));
}, 10 * 60 * 1000);

for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.on(signal, () => {
    clearInterval(timer);
    server.close(() => void db.close().then(() => process.exit(0)));
  });
}
