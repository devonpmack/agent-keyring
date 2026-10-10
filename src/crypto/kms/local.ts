import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { Kms } from './types.js';

// Development stand-in for a cloud KMS: AES-256-GCM with a key file kept outside
// the database. Refused in production by config validation.
export class LocalKms implements Kms {
  readonly keyId: string;
  private readonly key: Buffer;

  constructor(key: Buffer) {
    if (key.length !== 32) throw new Error('local KMS key must be 32 bytes');
    this.key = key;
    this.keyId = 'local:' + createHash('sha256').update(key).digest('hex').slice(0, 16);
  }

  static fromFile(path: string): LocalKms {
    if (!existsSync(path)) {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, randomBytes(32).toString('base64'), { mode: 0o600 });
    }
    return new LocalKms(Buffer.from(readFileSync(path, 'utf8').trim(), 'base64'));
  }

  async wrap(dataKey: Buffer, context: string): Promise<Buffer> {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(Buffer.from(context));
    const ct = Buffer.concat([cipher.update(dataKey), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), ct]);
  }

  async unwrap(wrapped: Buffer, keyId: string, context: string): Promise<Buffer> {
    if (keyId !== this.keyId) throw new Error('data key was wrapped by a different local key');
    const decipher = createDecipheriv('aes-256-gcm', this.key, wrapped.subarray(0, 12));
    decipher.setAAD(Buffer.from(context));
    decipher.setAuthTag(wrapped.subarray(12, 28));
    return Buffer.concat([decipher.update(wrapped.subarray(28)), decipher.final()]);
  }
}
