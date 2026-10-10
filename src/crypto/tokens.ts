import { createHash, randomBytes } from 'node:crypto';

export function randomToken(prefix: string, bytes = 32): string {
  return prefix + randomBytes(bytes).toString('base64url');
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// Crockford base32 without ambiguous characters, for IDs a human compares by eye.
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export function humanId(length = 10): string {
  const bytes = randomBytes(length);
  let out = '';
  for (const b of bytes) out += ALPHABET[b % 32];
  return out;
}
