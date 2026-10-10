import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { contexts, open, rewrap, seal } from '../src/crypto/envelope.js';
import { LocalKms } from '../src/crypto/kms/local.js';

describe('envelope encryption', () => {
  const kms = new LocalKms(randomBytes(32));

  it('round-trips and never stores plaintext', async () => {
    const sealed = await seal(kms, 'sk_test_fake_123', contexts.secret('w1', 's1'));
    expect(JSON.stringify(sealed)).not.toContain('sk_test_fake_123');
    expect(await open(kms, sealed, contexts.secret('w1', 's1'))).toBe('sk_test_fake_123');
  });

  it('uses a fresh data key per value', async () => {
    const a = await seal(kms, 'same', contexts.secret('w1', 's1'));
    const b = await seal(kms, 'same', contexts.secret('w1', 's1'));
    expect(a.dek).not.toBe(b.dek);
    expect(a.ct).not.toBe(b.ct);
  });

  it('refuses a ciphertext moved to another secret or workspace', async () => {
    const sealed = await seal(kms, 'value', contexts.secret('w1', 's1'));
    await expect(open(kms, sealed, contexts.secret('w1', 's2'))).rejects.toThrow();
    await expect(open(kms, sealed, contexts.secret('w2', 's1'))).rejects.toThrow();
  });

  it('cannot be opened without the master key', async () => {
    const sealed = await seal(kms, 'value', contexts.secret('w1', 's1'));
    await expect(open(new LocalKms(randomBytes(32)), sealed, contexts.secret('w1', 's1'))).rejects.toThrow();
  });

  it('rewraps the data key under a new master key without changing the value', async () => {
    const sealed = await seal(kms, 'value', contexts.secret('w1', 's1'));
    const newKms = new LocalKms(randomBytes(32));
    // A rotation deployment can unwrap old keys and wrap with the new one.
    const both = { keyId: newKms.keyId, wrap: newKms.wrap.bind(newKms), unwrap: (w: Buffer, id: string, c: string) => (id === kms.keyId ? kms.unwrap(w, id, c) : newKms.unwrap(w, id, c)) };
    const next = await rewrap(both, sealed, contexts.secret('w1', 's1'));
    expect(next.ct).toBe(sealed.ct);
    expect(next.kid).toBe(newKms.keyId);
    expect(await open(newKms, next, contexts.secret('w1', 's1'))).toBe('value');
  });
});
