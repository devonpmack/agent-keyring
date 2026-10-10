import { KeyManagementServiceClient } from '@google-cloud/kms';
import type { Kms } from './types.js';

type GcpKmsClient = Pick<KeyManagementServiceClient, 'encrypt' | 'decrypt'>;

// keyName is a CryptoKey resource name. GCP picks the primary version on
// encrypt and records it inside the ciphertext, so rotation needs no schema change.
export class GcpKms implements Kms {
  constructor(
    readonly keyId: string,
    private readonly client: GcpKmsClient = new KeyManagementServiceClient(),
  ) {}

  async wrap(dataKey: Buffer, context: string): Promise<Buffer> {
    const [res] = await this.client.encrypt({
      name: this.keyId,
      plaintext: dataKey,
      additionalAuthenticatedData: Buffer.from(context),
    });
    if (!res.ciphertext) throw new Error('KMS encrypt returned no ciphertext');
    return Buffer.from(res.ciphertext as Uint8Array);
  }

  async unwrap(wrapped: Buffer, keyId: string, context: string): Promise<Buffer> {
    const [res] = await this.client.decrypt({
      name: keyId,
      ciphertext: wrapped,
      additionalAuthenticatedData: Buffer.from(context),
    });
    if (!res.plaintext) throw new Error('KMS decrypt returned no plaintext');
    return Buffer.from(res.plaintext as Uint8Array);
  }
}
