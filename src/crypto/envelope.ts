import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { Kms } from './kms/types.js';

// What lands in the database. A random 256-bit data key encrypts the value with
// AES-256-GCM; the KMS wraps the data key. Both layers bind `context` as AAD.
export type Sealed = {
  v: 1;
  kid: string;
  dek: string;
  iv: string;
  tag: string;
  ct: string;
};

export async function seal(kms: Kms, plaintext: string, context: string): Promise<Sealed> {
  const dataKey = randomBytes(32);
  try {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', dataKey, iv);
    cipher.setAAD(Buffer.from(context));
    const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    return {
      v: 1,
      kid: kms.keyId,
      dek: (await kms.wrap(dataKey, context)).toString('base64'),
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      ct: ct.toString('base64'),
    };
  } finally {
    dataKey.fill(0);
  }
}

export async function open(kms: Kms, sealed: Sealed, context: string): Promise<string> {
  const dataKey = await kms.unwrap(Buffer.from(sealed.dek, 'base64'), sealed.kid, context);
  try {
    const decipher = createDecipheriv('aes-256-gcm', dataKey, Buffer.from(sealed.iv, 'base64'));
    decipher.setAAD(Buffer.from(context));
    decipher.setAuthTag(Buffer.from(sealed.tag, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(sealed.ct, 'base64')), decipher.final()]).toString('utf8');
  } finally {
    dataKey.fill(0);
  }
}

// Re-wraps the data key under the current master key without touching the value.
export async function rewrap(kms: Kms, sealed: Sealed, context: string): Promise<Sealed> {
  const dataKey = await kms.unwrap(Buffer.from(sealed.dek, 'base64'), sealed.kid, context);
  try {
    return { ...sealed, kid: kms.keyId, dek: (await kms.wrap(dataKey, context)).toString('base64') };
  } finally {
    dataKey.fill(0);
  }
}

export const contexts = {
  secret: (workspaceId: string, secretId: string) => `agent-keyring:v1:secret:${workspaceId}:${secretId}`,
  userTotp: (userId: string) => `agent-keyring:v1:user-totp:${userId}`,
};
