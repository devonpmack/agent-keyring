import { readFileSync } from 'node:fs';
import { z } from 'zod';

// Each value may also be supplied as NAME_FILE pointing at a mounted secret
// (Cloud Run secret volumes, Docker/Kubernetes secrets), so service credentials
// never need to live in env files or the repo.
function readEnv(name: string): string | undefined {
  const file = process.env[`${name}_FILE`];
  if (file) return readFileSync(file, 'utf8').trim();
  const value = process.env[name];
  return value === '' ? undefined : value;
}

const ConfigSchema = z
  .object({
    nodeEnv: z.enum(['development', 'production', 'test']).default('development'),
    port: z.coerce.number().int().positive().default(8080),
    baseUrl: z.url().transform(u => u.replace(/\/$/, '')),
    mode: z.enum(['self_hosted', 'managed']).default('self_hosted'),
    ownerEmail: z.email().optional(),
    databaseUrl: z.string().min(1),
    trustProxy: z.coerce.number().int().min(0).default(0),
    google: z.object({
      issuer: z.url().default('https://accounts.google.com'),
      clientId: z.string().min(1),
      clientSecret: z.string().min(1),
    }),
    kms: z.discriminatedUnion('provider', [
      z.object({ provider: z.literal('local'), keyFile: z.string().min(1) }),
      z.object({ provider: z.literal('gcp'), keyName: z.string().min(1) }),
      z.object({ provider: z.literal('aws'), keyId: z.string().min(1), region: z.string().optional() }),
    ]),
    allowLocalKmsInProduction: z.boolean().default(false),
    notifyWebhookUrl: z.url().optional(),
  })
  .superRefine((c, ctx) => {
    if (c.mode === 'self_hosted' && !c.ownerEmail) {
      ctx.addIssue({ code: 'custom', message: 'OWNER_EMAIL is required in self_hosted mode', path: ['ownerEmail'] });
    }
    if (c.nodeEnv === 'production' && c.kms.provider === 'local' && !c.allowLocalKmsInProduction) {
      ctx.addIssue({ code: 'custom', message: 'KMS_PROVIDER=local is for development only', path: ['kms'] });
    }
    if (c.nodeEnv === 'production' && c.databaseUrl.startsWith('pglite:')) {
      ctx.addIssue({ code: 'custom', message: 'DATABASE_URL=pglite: is for development only', path: ['databaseUrl'] });
    }
    if (c.nodeEnv === 'production' && !c.baseUrl.startsWith('https://')) {
      ctx.addIssue({ code: 'custom', message: 'BASE_URL must be https in production', path: ['baseUrl'] });
    }
  });

export type Config = z.infer<typeof ConfigSchema>;

function readKmsEnv() {
  const provider = readEnv('KMS_PROVIDER') ?? 'local';
  if (provider === 'gcp') return { provider, keyName: readEnv('GCP_KMS_KEY_NAME') };
  if (provider === 'aws') return { provider, keyId: readEnv('AWS_KMS_KEY_ID'), region: readEnv('AWS_REGION') };
  return { provider, keyFile: readEnv('LOCAL_KMS_KEY_FILE') ?? '.data/local-kms.key' };
}

export function loadConfig(): Config {
  return ConfigSchema.parse({
    nodeEnv: readEnv('NODE_ENV'),
    port: readEnv('PORT'),
    baseUrl: readEnv('BASE_URL'),
    mode: readEnv('MODE'),
    ownerEmail: readEnv('OWNER_EMAIL')?.toLowerCase(),
    databaseUrl: readEnv('DATABASE_URL'),
    trustProxy: readEnv('TRUST_PROXY'),
    google: {
      issuer: readEnv('GOOGLE_ISSUER'),
      clientId: readEnv('GOOGLE_CLIENT_ID'),
      clientSecret: readEnv('GOOGLE_CLIENT_SECRET'),
    },
    kms: readKmsEnv(),
    allowLocalKmsInProduction: readEnv('ALLOW_LOCAL_KMS_IN_PRODUCTION') === 'true',
    notifyWebhookUrl: readEnv('NOTIFY_WEBHOOK_URL'),
  });
}
